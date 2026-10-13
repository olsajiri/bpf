// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>
#include <errno.h>

char _license[] SEC("license") = "GPL";

extern enum libbpf_tristate CONFIG_DEBUG_INFO_BTF_INLINE __kconfig __weak;

/* Keep CONFIG_DEBUG_INFO_BTF_INLINE in the generated skeleton's kconfig. */
int unused(void)
{
	return CONFIG_DEBUG_INFO_BTF_INLINE == TRI_YES ? 0 : 1;
}

__u32 inline_probe_pid;
__u32 inline_probe_count;
__u32 inline_args_mask;
__u32 inline_args_errors;
__u32 inline_args_count;
__u32 regular_args_errors;
__u32 regular_args_count;

SEC("kprobe.multi")
int test_kprobe_inline(struct pt_regs *ctx)
{
	if (bpf_get_current_pid_tgid() >> 32 != inline_probe_pid)
		return 0;

	inline_probe_count++;
	return 0;
}

SEC("kprobe.multi")
int test_kprobe_inline_args(struct pt_regs *ctx)
{
	__u64 arg1 = 0, arg2 = 0, arg3 = 0, invalid = 0;
	__u64 nr_args;

	if (bpf_get_current_pid_tgid() >> 32 != inline_probe_pid)
		return 0;

	inline_args_count++;
	nr_args = bpf_get_func_arg_cnt(ctx);
	if (nr_args != 3 ||
	    bpf_get_func_arg(ctx, 0, &arg1) ||
	    bpf_get_func_arg(ctx, 1, &arg2) ||
	    bpf_get_func_arg(ctx, 2, &arg3) ||
	    bpf_get_func_arg(ctx, 3, &invalid) != -EINVAL) {
		inline_args_errors++;
		return 0;
	}

	if (arg1 == 0x11 && arg2 == 0x111 && arg3 == 0x1111)
		inline_args_mask |= 1;
	else if (arg1 == 0x22 && arg2 == 0x222 && arg3 == 0x2222)
		inline_args_mask |= 2;
	else if (arg1 == 0x33 && arg2 == 0x333 && arg3 == 0x3333)
		inline_args_mask |= 4;
	else
		inline_args_errors++;
	return 0;
}

SEC("kprobe.multi")
int test_kprobe_multi_regular_args(struct pt_regs *ctx)
{
	__u64 arg = 0, invalid = 0;

	if (bpf_get_current_pid_tgid() >> 32 != inline_probe_pid)
		return 0;

	regular_args_count++;
	if (bpf_get_func_arg_cnt(ctx) != 1 ||
	    bpf_get_func_arg(ctx, 0, &arg) || arg != 1 ||
	    bpf_get_func_arg(ctx, 1, &invalid) != -EINVAL)
		regular_args_errors++;
	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(trigger)
{
	return 0;
}
