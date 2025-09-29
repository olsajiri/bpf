// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018 Facebook

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH         127
#endif

typedef __u64 stack_trace_t[PERF_MAX_STACK_DEPTH];

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, stack_trace_t);
} stack_amap SEC(".maps");

/*
 * No tests in here, just to trigger 'bpf_fentry_test*'
 * through tracing test_run.
 */
SEC("fentry/bpf_modify_return_test")
int BPF_PROG(trigger)
{
	return 0;
}

static void check(void *ctx)
{
	__u32 max_len = PERF_MAX_STACK_DEPTH * sizeof(__u64);
	unsigned long *entry;
	long err = -1;
	__u32 key = 0;

	entry = bpf_map_lookup_elem(&stack_amap, &key);
	if (entry)
		err = bpf_get_stack(ctx, entry, max_len, 0);

	return err > 0 && entry[0] != entry[1];
}

bool test_result_fentry;

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test_fentry)
{
	test_result_fentry = check(ctx);
	return 0;
}

bool test_result_event;

SEC("perf_event")
int oncpu_hash_map(struct pt_regs *args)
{
	test_result_event = check(ctx);
	return 0;
}

char _license[] SEC("license") = "GPL";
