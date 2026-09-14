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
#include <linux/vmalloc.h>

static int __init btf_vmlinux_inline_init(void)
{
#if IS_BUILTIN(CONFIG_DEBUG_INFO_BTF_INLINE)
	struct btf *btf;
	const void *data;
	void *sysfs_data;
	struct bin_attribute *attr;
	u32 data_size;

	btf = bpf_get_btf_vmlinux_inline();
	if (IS_ERR(btf)) {
		pr_warn("failed to parse vmlinux inline BTF: %ld\n", PTR_ERR(btf));
		return 0;
	}
	if (!btf)
		return 0;

	data = btf_raw_data(btf, &data_size);
	if (!data_size)
		return 0;

	sysfs_data = vmalloc_user(data_size);
	if (!sysfs_data)
		return 0;
	memcpy(sysfs_data, data, data_size);
	attr = sysfs_btf_add("vmlinux.inline", sysfs_data, data_size, true, NULL);
	if (IS_ERR(attr))
		vfree(sysfs_data);
#endif
	return 0;
}
subsys_initcall(btf_vmlinux_inline_init);

MODULE_DESCRIPTION("BTF inline information for vmlinux");
MODULE_LICENSE("GPL");
