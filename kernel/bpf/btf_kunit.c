// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026, Oracle and/or its affiliates. */

#include <kunit/test.h>
#include <linux/bpf.h>
#include <linux/btf.h>

static void btf_vmlinux_inline_test(struct kunit *test)
{
	struct btf *inline_btf, *vmlinux_btf;
	const struct btf_type *t;
	bool has_loc_param = false;
	bool has_loc_proto = false;
	bool has_locsec = false;
	u32 start_id, nr_types, i;
	int locsec_id;

	inline_btf = bpf_get_btf_vmlinux_inline();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, inline_btf);

	vmlinux_btf = bpf_get_btf_vmlinux();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmlinux_btf);
	KUNIT_EXPECT_PTR_EQ(test, inline_btf, bpf_get_btf_vmlinux_inline());
	KUNIT_EXPECT_PTR_EQ(test, btf_base_btf(inline_btf), vmlinux_btf);
	KUNIT_EXPECT_TRUE(test, btf_is_vmlinux_inline(inline_btf));
	KUNIT_EXPECT_FALSE(test, btf_is_module(inline_btf));
	KUNIT_EXPECT_EQ(test, btf_obj_id(inline_btf), 0U);

	/* Skip the canonical BTF and inspect only inline BTF's own types. */
	start_id = btf_nr_types(btf_base_btf(inline_btf));
	nr_types = btf_nr_types(inline_btf);
	for (i = start_id; i < nr_types; i++) {
		t = btf_type_by_id(inline_btf, i);
		KUNIT_ASSERT_NOT_NULL(test, t);

		switch (btf_kind(t)) {
		case BTF_KIND_LOC_PARAM:
			has_loc_param = true;
			break;
		case BTF_KIND_LOC_PROTO:
			has_loc_proto = true;
			break;
		case BTF_KIND_LOCSEC:
			has_locsec = true;
			break;
		}
	}

	KUNIT_EXPECT_TRUE(test, has_loc_param);
	KUNIT_EXPECT_TRUE(test, has_loc_proto);
	KUNIT_EXPECT_TRUE(test, has_locsec);

	locsec_id = btf_find_by_name_kind(inline_btf, ".text", BTF_KIND_LOCSEC);
	KUNIT_ASSERT_GT(test, locsec_id, 0);
	t = btf_type_by_id(inline_btf, locsec_id);
	KUNIT_ASSERT_NOT_NULL(test, t);
	KUNIT_EXPECT_GT(test, btf_type_vlen(t), 0);
}

static struct kunit_case btf_vmlinux_inline_test_cases[] = {
	KUNIT_CASE(btf_vmlinux_inline_test),
	{}
};

static struct kunit_suite btf_vmlinux_inline_test_suite = {
	.name = "btf_vmlinux_inline",
	.test_cases = btf_vmlinux_inline_test_cases,
};

kunit_test_suite(btf_vmlinux_inline_test_suite);

MODULE_LICENSE("GPL");
