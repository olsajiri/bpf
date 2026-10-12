// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

char _license[] SEC("license") = "GPL";

extern enum libbpf_tristate CONFIG_DEBUG_INFO_BTF_INLINE __kconfig __weak;

/* Keep CONFIG_DEBUG_INFO_BTF_INLINE in the generated skeleton's kconfig. */
int unused(void)
{
	return CONFIG_DEBUG_INFO_BTF_INLINE == TRI_YES ? 0 : 1;
}

__u32 inline_probe_pid;
__u32 inline_probe_count;

SEC("kprobe.multi")
int test_kprobe_inline(struct pt_regs *ctx)
{
	if (bpf_get_current_pid_tgid() >> 32 != inline_probe_pid)
		return 0;

	inline_probe_count++;
	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(trigger)
{
	return 0;
}
