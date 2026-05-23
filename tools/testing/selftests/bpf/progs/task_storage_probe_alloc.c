// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define LARGE_VALUE_SIZE	(16 * 1024)
#define SINGLE_UPROBE_MARKER	1
#define UPROBE_MULTI_MARKER	2

struct large_value {
	__u64 marker;
	__u8 data[LARGE_VALUE_SIZE - sizeof(__u64)];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct large_value);
} single_uprobe_storage SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct large_value);
} uprobe_multi_storage SEC(".maps");

int target_pid;
int single_uprobe_runs;
int single_uprobe_nulls;
int single_uprobe_bad;
int uprobe_multi_runs;
int uprobe_multi_nulls;
int uprobe_multi_bad;

static __always_inline bool is_target_task(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == target_pid;
}

SEC("uprobe")
int single_uprobe(struct pt_regs *ctx)
{
	struct task_struct *task;
	struct large_value *value;

	if (!is_target_task())
		return 0;

	task = bpf_get_current_task_btf();
	value = bpf_task_storage_get(&single_uprobe_storage, task, NULL,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!value) {
		single_uprobe_nulls++;
		return 0;
	}

	value->marker = SINGLE_UPROBE_MARKER;
	value->data[0] = SINGLE_UPROBE_MARKER;
	value->data[sizeof(value->data) - 1] = SINGLE_UPROBE_MARKER;

	if (value->marker != SINGLE_UPROBE_MARKER ||
	    value->data[0] != SINGLE_UPROBE_MARKER ||
	    value->data[sizeof(value->data) - 1] != SINGLE_UPROBE_MARKER)
		single_uprobe_bad++;
	else
		single_uprobe_runs++;

	return 0;
}

SEC("uprobe.multi")
int uprobe_multi(struct pt_regs *ctx)
{
	struct task_struct *task;
	struct large_value *value;

	if (!is_target_task())
		return 0;

	task = bpf_get_current_task_btf();
	value = bpf_task_storage_get(&uprobe_multi_storage, task, NULL,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!value) {
		uprobe_multi_nulls++;
		return 0;
	}

	value->marker = UPROBE_MULTI_MARKER;
	value->data[0] = UPROBE_MULTI_MARKER;
	value->data[sizeof(value->data) - 1] = UPROBE_MULTI_MARKER;

	if (value->marker != UPROBE_MULTI_MARKER ||
	    value->data[0] != UPROBE_MULTI_MARKER ||
	    value->data[sizeof(value->data) - 1] != UPROBE_MULTI_MARKER)
		uprobe_multi_bad++;
	else
		uprobe_multi_runs++;

	return 0;
}

char _license[] SEC("license") = "GPL";
