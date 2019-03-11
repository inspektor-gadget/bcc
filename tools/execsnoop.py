#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# execsnoop Trace new processes via exec() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: execsnoop [-h] [-t] [-x] [-n NAME]
#
# This currently will print up to a maximum of 19 arguments, plus the process
# name, so 20 fields in total (MAXARG).
#
# This won't catch all new processes: an application may fork() but not exec().
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import ArgString, printb
import bcc.utils as utils
import argparse
import re
import time
from collections import defaultdict
import os
import sys
import fcntl


# arguments
examples = """examples:
    ./execsnoop              # trace all exec() syscalls
    ./execsnoop -x           # include failed exec()s
    ./execsnoop -t           # include timestamps
    ./execsnoop -q           # add "quotemarks" around arguments
    ./execsnoop -c $CID      # only trace CID (64 hex)
    ./execsnoop -b app=web   # only trace pods with this label
    ./execsnoop -n main      # only print command lines containing "main"
    ./execsnoop -l tpkg      # only print command where arguments contains "tpkg"
"""
parser = argparse.ArgumentParser(
    description="Trace exec() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-x", "--fails", action="store_true",
    help="include failed exec()s")
parser.add_argument("-q", "--quote", action="store_true",
    help="Add quotemarks (\") around arguments."
    )
parser.add_argument("-c", "--containerid",
    help="trace this container ID only")
parser.add_argument("-b", "--label",
    help="trace pods with this label only")
parser.add_argument("-n", "--name",
    type=ArgString,
    help="only print commands matching this name (regex), any arg")
parser.add_argument("-l", "--line",
    type=ArgString,
    help="only print commands where arg contains this line (regex)")
parser.add_argument("--max-args", default="20",
    help="maximum number of arguments parsed and displayed, defaults to 20")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

typedef char containerid[64];

typedef char text64[64];

BPF_HASH(pidmap, u32, containerid);         // DEFINE_PIDMAP        // EXTERNAL_MAP:pidmap,/sys/fs/bpf/pidmap,90
BPF_HASH(containermap, containerid, u32);   // DEFINE_CONTAINERMAP  // EXTERNAL_MAP:containermap,/sys/fs/bpf/containermap,91
BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    containerid *cid = pidmap.lookup(&pid); // DEFINE_PIDMAP
 
    CONTAINERID_FILTER
    LABEL_FILTER

    data.pid = pid;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    containerid *cid = pidmap.lookup(&pid); // DEFINE_PIDMAP
 
    CONTAINERID_FILTER
    LABEL_FILTER

    data.pid = pid;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

bpf_text = bpf_text.replace("MAXARG", args.max_args)

if args.containerid:
    if len(args.containerid) != 64:
        exit("Bad size for containerid: %s" % args.containerid)
    bpf_text = bpf_text.replace('CONTAINERID_FILTER',
        '''if (cid == 0 || %s)
              { return 0; }
        ''' % (
           " || ".join([ "(*cid)[%s] != '%s'" % (str(i), args.containerid[i]) for i in range(64)])
        ))
else:
    bpf_text = bpf_text.replace('CONTAINERID_FILTER', '')

if args.label:
    label_kv = args.label.split("=", 2)
    if len(label_kv) != 2 or len(label_kv[0]) > 64 or len(label_kv[1]) > 64:
        exit("Bad key-value label selector: %s" % args.label)
    key_with_spaces = label_kv[0] + " " * (64 - len(label_kv[0]))
    value_len = len(label_kv[1])
    value_with_spaces = label_kv[1] + " " * (64 - len(label_kv[1]))
    bpf_text = bpf_text.replace('LABEL_FILTER',
        '''if (cid == 0) {
                return 0;
              }
           u32 *innermap = containermap.lookup(cid);
           if (innermap == NULL) { return 0; }

           text64 textkey = {%s};
           text64 *textvalue = bpf_map_lookup_elem_((uintptr_t)innermap, &textkey[0]);
           if (textvalue == NULL) { return 0; }
           if (%s) { return 0; }
        ''' % (
           "'" + "', '".join(list(key_with_spaces)) + "'",
           " || ".join([ "textvalue[0][%s] != '%s'" % (str(i), value_with_spaces[i]) for i in range(min(64, value_len+1))])
        ))
else:
    bpf_text = bpf_text.replace('LABEL_FILTER', '')

if not (args.containerid or args.label):
    bpf_text = '\n'.join(x for x in bpf_text.split('\n')
        if 'DEFINE_PIDMAP' not in x)
if not args.label:
    bpf_text = '\n'.join(x for x in bpf_text.split('\n')
        if 'DEFINE_CONTAINERMAP' not in x)

if args.ebpf:
    print(bpf_text)
    exit()

for x in bpf_text.split('\n'):
  if 'EXTERNAL_MAP' not in x:
    continue
  external_params = x.split('EXTERNAL_MAP:')[1].split(',')
  map_name = external_params[0]
  pin_path = external_params[1]
  external_fd = int(external_params[2])
  if not os.path.islink("/proc/self/fd/" + str(external_fd)):
    os.execvp("bpftool", ["bpftool", "map", "exec", "pinned", pin_path, "fd", str(external_fd), "cmd", "--"] + sys.argv)

# initialize BPF
b = BPF(text=bpf_text)

for x in bpf_text.split('\n'):
  if 'EXTERNAL_MAP' not in x:
    continue
  external_params = x.split('EXTERNAL_MAP:')[1].split(',')
  map_name = external_params[0]
  pin_path = external_params[1]
  external_fd = int(external_params[2])
  def set_cloexec(fd, cloexec=True):
    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    if cloexec:
      flags |= fcntl.FD_CLOEXEC
    else:
      flags &= ~fcntl.FD_CLOEXEC
    fcntl.fcntl(fd, fcntl.F_SETFD, flags)
  for i in range(3, 30):
    set_cloexec(i, cloexec=False)
    ret = os.system("bpftool map show fd " + str(i) + " | grep -q 'name " + map_name + "' 2>/dev/null")
    set_cloexec(i, cloexec=True)
    if ret == 0:
      os.dup2(external_fd, i)
      break

execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

# header
if args.timestamp:
    print("%-8s" % ("TIME(s)"), end="")
print("%-16s %-6s %-6s %3s %s" % ("PCOMM", "PID", "PPID", "RET", "ARGS"))

class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

start_ts = time.time()
argv = defaultdict(list)

# This is best-effort PPID matching. Short-lived processes may exit
# before we get a chance to read the PPID.
# This is a fallback for when fetching the PPID from task->real_parent->tgip
# returns 0, which happens in some kernel versions.
def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    skip = False

    if event.type == EventType.EVENT_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        if event.retval != 0 and not args.fails:
            skip = True
        if args.name and not re.search(bytes(args.name), event.comm):
            skip = True
        if args.line and not re.search(bytes(args.line),
                                       b' '.join(argv[event.pid])):
            skip = True
        if args.quote:
            argv[event.pid] = [
                b"\"" + arg.replace(b"\"", b"\\\"") + b"\""
                for arg in argv[event.pid]
            ]

        if not skip:
            if args.timestamp:
                print("%-8.3f" % (time.time() - start_ts), end="")
            ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
            ppid = b"%d" % ppid if ppid > 0 else b"?"
            argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
            printb(b"%-16s %-6d %-6s %3d %s" % (event.comm, event.pid,
                   ppid, event.retval, argv_text))
        try:
            del(argv[event.pid])
        except Exception:
            pass


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
