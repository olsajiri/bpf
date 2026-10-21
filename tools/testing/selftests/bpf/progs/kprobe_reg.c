// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("kprobe")
int kprobe_reg(struct pt_regs *ctx)
{
	(void)ctx;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
