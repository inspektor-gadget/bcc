#!/usr/bin/python
#
# tcpv4tracer   Trace TCP connections.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpv4tracer [-h] [-v] [-p PID] [-N NETNS]
#
# Copyright 2016 Kinvolk GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License")
from __future__ import print_function
from bcc import BPF

import argparse
import ctypes
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

parser = argparse.ArgumentParser(
    description="Trace TCP connections",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-N", "--netns", default=0, type=int,
    help="trace this Network Namespace only")
parser.add_argument("-v", "--verbose", action="store_true",
    help="include Network Namespace in the output")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>

#define TCP_EVENT_TYPE_CONNECT 1
#define TCP_EVENT_TYPE_ACCEPT  2
#define TCP_EVENT_TYPE_CLOSE   3

struct tcp_ipv4_event_t {
        u32 type;
        u32 pid;
        char comm[TASK_COMM_LEN];
        u8 ip;
        u32 saddr;
        u32 daddr;
        u16 sport;
        u16 dport;
        u32 netns;
};
BPF_PERF_OUTPUT(tcp_ipv4_event);

struct tcp_ipv6_event_t {
        u32 type;
        u32 pid;
        char comm[TASK_COMM_LEN];
        u8 ip;
        unsigned __int128 saddr;
        unsigned __int128 daddr;
        u16 sport;
        u16 dport;
        u32 netns;
};
BPF_PERF_OUTPUT(tcp_ipv6_event);

BPF_HASH(connectsock, u64, struct sock *);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
        u64 pid = bpf_get_current_pid_tgid();

        ##FILTER_PID##

        // stash the sock ptr for lookup on return
        connectsock.update(&pid, &sk);

        return 0;
}

static int trace_connect_return(struct pt_regs *ctx, unsigned char ipver)
{
        int ret = PT_REGS_RC(ctx);
        u64 pid = bpf_get_current_pid_tgid();

        struct sock **skpp;
        skpp = connectsock.lookup(&pid);
        if (skpp == 0) {
                return 0;       // missed entry
        }

        if (ret != 0) {
                // failed to send SYNC packet, may not have populated
                // socket __sk_common.{skc_rcv_saddr, ...}
                connectsock.delete(&pid);
                return 0;
        }

        // pull in details
        struct sock *skp = *skpp;
        struct ns_common *ns;
        u32 net_ns_inum = 0;
        u16 sport = 0, dport = 0;

        // Get network namespace id, if kernel supports it
        #ifdef CONFIG_NET_NS
                possible_net_t skc_net;
                bpf_probe_read(&skc_net, sizeof(skc_net), &skp->__sk_common.skc_net);
                bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
        #else
                net_ns_inum = 0;
        #endif

        ##FILTER_NETNS##

        bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
        bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

        // if ports are 0, ignore
        if (sport == 0 || dport == 0) {
                return 0;
        }

        if (ipver == 4) {
                struct tcp_ipv4_event_t evt4 = { 0 };

                u32 saddr = 0, daddr = 0;
                bpf_probe_read(&saddr, sizeof(saddr),
                    &skp->__sk_common.skc_rcv_saddr);
                bpf_probe_read(&daddr, sizeof(daddr),
                    &skp->__sk_common.skc_daddr);

                // if addresses are 0, ignore
                if (saddr == 0 || daddr == 0) {
                        return 0;
                }

                evt4.type = TCP_EVENT_TYPE_CONNECT;
                evt4.pid = pid >> 32;
                evt4.ip = ipver;
                evt4.saddr = saddr;
                evt4.daddr = daddr;
                evt4.sport = ntohs(sport);
                evt4.dport = ntohs(dport);
                evt4.netns = net_ns_inum;
                bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));

                tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
        } else /* 6 */ {
                struct tcp_ipv6_event_t evt6 = { 0 };

                unsigned __int128 saddr = 0, daddr = 0;
                bpf_probe_read(&saddr, sizeof(saddr),
                    &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                bpf_probe_read(&daddr, sizeof(daddr),
                    &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

                // if addresses are 0, ignore
                if (saddr == 0 || daddr == 0) {
                        return 0;
                }

                evt6.type = TCP_EVENT_TYPE_CONNECT;
                evt6.pid = pid >> 32;
                evt6.ip = ipver;
                evt6.saddr = saddr;
                evt6.daddr = daddr;
                evt6.sport = ntohs(sport);
                evt6.dport = ntohs(dport);
                evt6.netns = net_ns_inum;
                bpf_get_current_comm(&evt6.comm, sizeof(evt6.comm));

                tcp_ipv6_event.perf_submit(ctx, &evt6, sizeof(evt6));
        }

        connectsock.delete(&pid);

        return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
        return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
        return trace_connect_return(ctx, 6);
}

int trace_close_entry(struct pt_regs *ctx, struct sock *sk)
{
        u64 pid = bpf_get_current_pid_tgid();

        ##FILTER_PID##

        // pull in details
        struct sock *skp;
        u32 saddr = 0, daddr = 0, net_ns_inum = 0;
        u16 sport = 0, dport = 0, family = 0;
        u8 ipver = 0;
        bpf_probe_read(&skp, sizeof(skp), &sk);

// Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS
        possible_net_t skc_net;
        bpf_probe_read(&skc_net, sizeof(skc_net), &skp->__sk_common.skc_net);
        bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#else
        net_ns_inum = 0;
#endif

        ##FILTER_NETNS##

        bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);
        bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
        bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);


        // if ports are 0, ignore
        if (sport == 0 || dport == 0) {
                return 0;
        }

        if (family == AF_INET) {
                ipver = 4;

                struct tcp_ipv4_event_t evt4 = { 0 };

                u32 saddr = 0, daddr = 0;
                bpf_probe_read(&saddr, sizeof(saddr),
                    &skp->__sk_common.skc_rcv_saddr);
                bpf_probe_read(&daddr, sizeof(daddr),
                    &skp->__sk_common.skc_daddr);

                // if addresses are 0, ignore
                if (saddr == 0 || daddr == 0) {
                        return 0;
                }

                evt4.type = TCP_EVENT_TYPE_CLOSE;
                evt4.pid = pid >> 32;
                evt4.ip = ipver;
                evt4.saddr = saddr;
                evt4.daddr = daddr;
                evt4.sport = ntohs(sport);
                evt4.dport = ntohs(dport);
                evt4.netns = net_ns_inum;
                bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));

                tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
        } else if (family == AF_INET6) {
                ipver = 6;

                struct tcp_ipv6_event_t evt6 = { 0 };

                unsigned __int128 saddr = 0, daddr = 0;
                bpf_probe_read(&saddr, sizeof(saddr),
                    &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                bpf_probe_read(&daddr, sizeof(daddr),
                    &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

                // if addresses are 0, ignore
                if (saddr == 0 || daddr == 0) {
                        return 0;
                }

                evt6.type = TCP_EVENT_TYPE_CLOSE;
                evt6.pid = pid >> 32;
                evt6.ip = ipver;
                evt6.saddr = saddr;
                evt6.daddr = daddr;
                evt6.sport = ntohs(sport);
                evt6.dport = ntohs(dport);
                evt6.netns = net_ns_inum;
                bpf_get_current_comm(&evt6.comm, sizeof(evt6.comm));

                tcp_ipv6_event.perf_submit(ctx, &evt6, sizeof(evt6));
        }
        // else drop

        return 0;
};

int trace_accept_return(struct pt_regs *ctx)
{
        struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
        u64 pid = bpf_get_current_pid_tgid();

        ##FILTER_PID##

        if (newsk == NULL) {
                return 0;
        }

        // check this is TCP
        u8 protocol = 0;
        // workaround for reading the sk_protocol bitfield:
        bpf_probe_read(&protocol, 1, (void *)((long)&newsk->sk_wmem_queued) - 3);
        if (protocol != IPPROTO_TCP)
                return 0;

        // pull in details
        u16 family = 0, lport = 0, dport = 0;
        u32 net_ns_inum = 0;
        u8 ipver = 0;
        bpf_probe_read(&family, sizeof(family), &newsk->__sk_common.skc_family);
        bpf_probe_read(&lport, sizeof(lport), &newsk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &newsk->__sk_common.skc_dport);

// Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS
        possible_net_t skc_net;
        bpf_probe_read(&skc_net, sizeof(skc_net), &newsk->__sk_common.skc_net);
        bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#else
        net_ns_inum = 0;
#endif

        ##FILTER_NETNS##

        if (family == AF_INET) {
                ipver = 4;

                struct tcp_ipv4_event_t evt4 = { 0 };

                u32 saddr = 0, daddr = 0;
                bpf_probe_read(&saddr, sizeof(saddr),
                    &newsk->__sk_common.skc_rcv_saddr);
                bpf_probe_read(&daddr, sizeof(daddr),
                    &newsk->__sk_common.skc_daddr);

                // if addresses are 0, ignore
                if (saddr == 0 || daddr == 0) {
                        return 0;
                }

                evt4.type = TCP_EVENT_TYPE_ACCEPT;
                evt4.pid = pid >> 32;
                evt4.ip = ipver;
                evt4.saddr = saddr;
                evt4.daddr = daddr;
                evt4.sport = lport;
                evt4.dport = ntohs(dport);
                evt4.netns = net_ns_inum;
                bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));

                tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
        } else if (family == AF_INET6) {
                ipver = 6;

                struct tcp_ipv6_event_t evt6 = { 0 };

                unsigned __int128 saddr = 0, daddr = 0;
                bpf_probe_read(&saddr, sizeof(saddr),
                    &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                bpf_probe_read(&daddr, sizeof(daddr),
                    &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

                // if addresses are 0, ignore
                if (saddr == 0 || daddr == 0) {
                        return 0;
                }

                evt6.type = TCP_EVENT_TYPE_ACCEPT;
                evt6.pid = pid >> 32;
                evt6.ip = ipver;
                evt6.saddr = saddr;
                evt6.daddr = daddr;
                evt6.sport = lport;
                evt6.dport = ntohs(dport);
                evt6.netns = net_ns_inum;
                bpf_get_current_comm(&evt6.comm, sizeof(evt6.comm));

                tcp_ipv6_event.perf_submit(ctx, &evt6, sizeof(evt6));
        }
        // else drop

        return 0;
}
"""

TASK_COMM_LEN = 16   # linux/sched.h
class TCPIPV4Evt(ctypes.Structure):
    _fields_ = [
            ("type", ctypes.c_uint),
            ("pid", ctypes.c_uint),
            ("comm", ctypes.c_char * TASK_COMM_LEN),
            ("ip", ctypes.c_ubyte),
            ("saddr", ctypes.c_uint),
            ("daddr", ctypes.c_uint),
            ("sport", ctypes.c_ushort),
            ("dport", ctypes.c_ushort),
            ("netns", ctypes.c_uint)
    ]

class TCPIPV6Evt(ctypes.Structure):
    _fields_ = [
            ("type", ctypes.c_uint),
            ("pid", ctypes.c_uint),
            ("comm", ctypes.c_char * TASK_COMM_LEN),
            ("ip", ctypes.c_ubyte),
            ("saddr", (ctypes.c_ulong * 2)),
            ("daddr", (ctypes.c_ulong * 2)),
            ("sport", ctypes.c_ushort),
            ("dport", ctypes.c_ushort),
            ("netns", ctypes.c_uint)
    ]

verbose_types = {"CN": "connect", "AC": "accept",
    "CL": "close", "UN": "unknown"}

def print_ipv4_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(TCPIPV4Evt)).contents
    if event.type == 1:
        type_str = "CN"
    elif event.type == 2:
        type_str = "AC"
    elif event.type == 3:
        type_str = "CL"
    else:
        type_str = "UN"

    if args.verbose:
        print("%-12s " % (verbose_types[type_str]), end="")
    else:
        print("%-2s " % (type_str), end="")

    print("%-6d %-16s %-2d %-16s %-16s %-6d %-6d" % (event.pid, event.comm.decode('utf-8'),
        event.ip,
        inet_ntop(AF_INET, pack("I", event.saddr)),
        inet_ntop(AF_INET, pack("I", event.daddr)),
        event.sport,
        event.dport), end="")
    if args.verbose:
        print(" %-8d" % event.netns)
    else:
        print()


def print_ipv6_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(TCPIPV6Evt)).contents
    if event.type == 1:
        type_str = "CN"
    elif event.type == 2:
        type_str = "AC"
    elif event.type == 3:
        type_str = "CL"
    else:
        type_str = "unknown-" + str(event.type)

    if args.verbose:
        print("%-12s " % (verbose_types[type_str]), end="")
    else:
        print("%-2s " % (type_str), end="")

    print("%-6d %-16s %-2d %-16s %-16s %-6d %-6d" % (event.pid, event.comm.decode('utf-8'),
        event.ip,
        inet_ntop(AF_INET6, event.saddr),
        inet_ntop(AF_INET6, event.daddr),
        event.sport,
        event.dport), end="")
    if args.verbose:
        print(" %-8d" % event.netns)
    else:
        print()

pid_filter = ""
netns_filter = ""

if args.pid:
    pid_filter = 'if (pid >> 32 != %d) { return 0; }' % args.pid
if args.netns:
    netns_filter = 'if (net_ns_inum != %d) { return 0; }' % args.netns

bpf_text = bpf_text.replace('##FILTER_PID##', pid_filter)
bpf_text = bpf_text.replace('##FILTER_NETNS##', netns_filter)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")
b.attach_kprobe(event="tcp_close", fn_name="trace_close_entry")
b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return")

# header
if args.verbose:
    print("%-12s %-6s %-16s %-2s %-16s %-16s %-6s %-6s %-8s" % ("TYPE",
          "PID", "COMM", "IP", "SADDR", "DADDR", "SPORT", "DPORT", "NETNS"))
else:
    print("%-2s %-6s %-16s %-2s %-16s %-16s %-6s %-6s" %
          ("T", "PID", "COMM", "IP", "SADDR", "DADDR", "SPORT", "DPORT"))

def inet_ntoa(addr):
    dq = ''
    for i in range(0, 4):
        dq = dq + str(addr & 0xff)
        if (i != 3):
            dq = dq + '.'
        addr = addr >> 8
    return dq

b["tcp_ipv4_event"].open_perf_buffer(print_ipv4_event)
b["tcp_ipv6_event"].open_perf_buffer(print_ipv6_event)
while True:
    b.kprobe_poll()
