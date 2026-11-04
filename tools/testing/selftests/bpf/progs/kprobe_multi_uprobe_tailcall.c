// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} progs SEC(".maps");

int target_runs;

SEC("kprobe.multi")
int entry(struct pt_regs *ctx)
{
	bpf_tail_call(ctx, &progs, 0);
	return 0;
}

SEC("kprobe.multi")
int target(struct pt_regs *ctx)
{
	volatile __u64 stack[32];

	stack[31] = 1;
	__sync_fetch_and_add(&target_runs, 1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
