// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026, Oracle and/or its affiliates. */
/*
 * Provide kernel BTF inline function information for use by BPF tools.
 */
#include <linux/btf.h>
#include <linux/bpf.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

static int __init btf_vmlinux_inline_init(void)
{
#if IS_BUILTIN(CONFIG_DEBUG_INFO_BTF_INLINE)
	struct btf *btf;
	const void *data;
	u32 data_size;

	btf = bpf_get_btf_vmlinux_inline();
	if (IS_ERR(btf)) {
		pr_warn("failed to parse vmlinux inline BTF: %ld\n", PTR_ERR(btf));
		return 0;
	}
	if (!btf)
		return 0;

	data = btf_raw_data(btf, &data_size);
	if (data_size)
		sysfs_btf_add("vmlinux.inline", (void *)data, data_size);
#endif
	return 0;
}
subsys_initcall(btf_vmlinux_inline_init);

#if IS_MODULE(CONFIG_DEBUG_INFO_BTF_INLINE)
static void __exit btf_vmlinux_inline_fini(void)
{
}
module_exit(btf_vmlinux_inline_fini);
#endif

MODULE_DESCRIPTION("BTF inline information for vmlinux");
MODULE_LICENSE("GPL");
