// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/kernel.h>

#include <asm/ptrace.h>

#ifdef CONFIG_X86_64
static const unsigned int dwarf_reg_offsets[] = {
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
#endif

int bpf_arch_dwarf_regval(struct pt_regs *regs, u32 regno, u64 *value)
{
#ifdef CONFIG_X86_64
	if (regno >= ARRAY_SIZE(dwarf_reg_offsets))
		return -EOPNOTSUPP;
	*value = regs_get_register(regs, dwarf_reg_offsets[regno]);
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}
