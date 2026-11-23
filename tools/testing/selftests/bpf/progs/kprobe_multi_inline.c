// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define MAX_HITS 16
#define MAX_ARGS 4

int pid = 0;

__u64 hits_ip[MAX_HITS];
__u64 hits_cookie[MAX_HITS];
__u32 hits_cnt = 0;

__u64 args_cnt[MAX_HITS];
__u64 args_val[MAX_HITS][MAX_ARGS];
long args_err[MAX_HITS][MAX_ARGS];

/*
 * No tests in here, just to trigger 'bpf_kprobe_multi_inline_test*'
 * through tracing test_run
 */
SEC("fentry/bpf_modify_return_test")
int BPF_PROG(trigger)
{
	return 0;
}

SEC("kprobe.multi")
int test_kprobe_inline(struct pt_regs *ctx)
{
	__u32 idx = hits_cnt;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	if (idx >= MAX_HITS)
		return 0;

	hits_ip[idx] = bpf_get_func_ip(ctx);
	hits_cookie[idx] = bpf_get_attach_cookie(ctx);
	hits_cnt = idx + 1;
	return 0;
}

SEC("kprobe.multi")
int test_kprobe_inline_args(struct pt_regs *ctx)
{
	__u32 idx = hits_cnt;
	__u64 val;
	int i;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	if (idx >= MAX_HITS)
		return 0;

	hits_ip[idx] = bpf_get_func_ip(ctx);
	hits_cookie[idx] = bpf_get_attach_cookie(ctx);
	args_cnt[idx] = bpf_get_func_arg_cnt(ctx);

	for (i = 0; i < MAX_ARGS; i++) {
		val = 0;
		args_err[idx][i] = bpf_get_func_arg(ctx, i, &val);
		args_val[idx][i] = val;
	}

	hits_cnt = idx + 1;
	return 0;
}

SEC("kprobe.session")
int test_session_inline(struct pt_regs *ctx)
{
	return 0;
}
