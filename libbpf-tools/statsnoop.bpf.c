// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Hengqi Chen
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "statsnoop.h"

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;
const volatile bool  trace_failed_only = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, const char *);
} values SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct statfs *);
} buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static int probe_entry(void *ctx, const char *pathname, struct statfs *statfs)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;
	__u32 tid = (__u32)id;

	if (!pathname)
		return 0;

	if (target_pid && target_pid != pid)
		return 0;

	bpf_map_update_elem(&values, &tid, &pathname, BPF_ANY);
	bpf_map_update_elem(&buf, &tid, &statfs, BPF_ANY);

	return 0;
};

static int probe_return(void *ctx, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;
	__u32 tid = (__u32)id;
	const char **pathname;
	struct statfs **statfs;
	struct event event = {};

	pathname = bpf_map_lookup_elem(&values, &tid);
	if (!pathname)
		return 0;

	statfs = bpf_map_lookup_elem(&buf, &tid);
	if (!statfs)
		return 0;

	if (trace_failed_only && ret >= 0) {
		bpf_map_delete_elem(&values, &tid);
		return 0;
	}

	event.pid = pid;
	event.ts_ns = bpf_ktime_get_ns();
	event.ret = ret;

	// TODO: nasty hack as type is the first field in struct statfs
	bpf_probe_read_user(&event.type, sizeof(event.type), *statfs);

	// only trace CIFS (CIFS_MAGIC_NUMBER)
	if (event.type != 0xff534d42) {
		goto end;
	}

	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user_str(event.pathname, sizeof(event.pathname), *pathname);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

end:
	bpf_map_delete_elem(&values, &tid);
	bpf_map_delete_elem(&buf, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_statfs")
int handle_statfs_entry(struct trace_event_raw_sys_enter *ctx)
{
	return probe_entry(ctx, (const char *)ctx->args[0], (struct statfs *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_statfs")
int handle_statfs_return(struct trace_event_raw_sys_exit *ctx)
{
	return probe_return(ctx, (int)ctx->ret);
}

//SEC("tracepoint/syscalls/sys_enter_newstat")
//int handle_newstat_entry(struct trace_event_raw_sys_enter *ctx)
//{
//	return probe_entry(ctx, (const char *)ctx->args[0], (struct statfs *)ctx->args[0]);
//}
//
//SEC("tracepoint/syscalls/sys_exit_newstat")
//int handle_newstat_return(struct trace_event_raw_sys_exit *ctx)
//{
//	return probe_return(ctx, (int)ctx->ret);
//}

char LICENSE[] SEC("license") = "GPL";
