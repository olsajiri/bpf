// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/stddef.h>

/* DWARF register numbers as defined by x86-64 psABI. */
static const unsigned int dwarf_regs[] = {
	offsetof(struct pt_regs, ax),
	offsetof(struct pt_regs, dx),
	offsetof(struct pt_regs, cx),
	offsetof(struct pt_regs, bx),
	offsetof(struct pt_regs, si),
	offsetof(struct pt_regs, di),
	offsetof(struct pt_regs, bp),
	offsetof(struct pt_regs, sp),
	offsetof(struct pt_regs, r8),
	offsetof(struct pt_regs, r9),
	offsetof(struct pt_regs, r10),
	offsetof(struct pt_regs, r11),
	offsetof(struct pt_regs, r12),
	offsetof(struct pt_regs, r13),
	offsetof(struct pt_regs, r14),
	offsetof(struct pt_regs, r15),
	offsetof(struct pt_regs, ip),
};

int bpf_arch_dwarf_regval(struct pt_regs *regs, u32 regno, u64 *value)
{
	if (regno >= ARRAY_SIZE(dwarf_regs))
		return -EOPNOTSUPP;
	*value = regs_get_register(regs, dwarf_regs[regno]);
	return 0;
}
