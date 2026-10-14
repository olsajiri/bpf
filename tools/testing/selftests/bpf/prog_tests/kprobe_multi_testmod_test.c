// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>
#include "kprobe_multi.skel.h"
#include "kprobe_multi_inline.skel.h"
#include "trace_helpers.h"
#include "bpf/libbpf_internal.h"

#define BTF_INLINE_PATH "/sys/kernel/btf/vmlinux.inline"
#define INLINE_SCAN_ENV "BPF_KPROBE_MULTI_INLINE_SCAN"

struct inline_func_stat {
	const char *name;
	__u32 loc_count;
	int attach_err;
	__u64 attach_time_ns;
};

static int inline_func_stat_cmp(const void *a, const void *b)
{
	const struct inline_func_stat *func_a = a;
	const struct inline_func_stat *func_b = b;

	return strcmp(func_a->name, func_b->name);
}

static struct ksyms *ksyms;

static void kprobe_multi_testmod_check(struct kprobe_multi *skel)
{
	ASSERT_EQ(skel->bss->kprobe_testmod_test1_result, 1, "kprobe_test1_result");
	ASSERT_EQ(skel->bss->kprobe_testmod_test2_result, 1, "kprobe_test2_result");
	ASSERT_EQ(skel->bss->kprobe_testmod_test3_result, 1, "kprobe_test3_result");

	ASSERT_EQ(skel->bss->kretprobe_testmod_test1_result, 1, "kretprobe_test1_result");
	ASSERT_EQ(skel->bss->kretprobe_testmod_test2_result, 1, "kretprobe_test2_result");
	ASSERT_EQ(skel->bss->kretprobe_testmod_test3_result, 1, "kretprobe_test3_result");
}

static void test_testmod_attach_api(struct bpf_kprobe_multi_opts *opts)
{
	struct kprobe_multi *skel = NULL;

	skel = kprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_raw_skel_load"))
		return;

	skel->bss->pid = getpid();

	skel->links.test_kprobe_testmod = bpf_program__attach_kprobe_multi_opts(
						skel->progs.test_kprobe_testmod,
						NULL, opts);
	if (!skel->links.test_kprobe_testmod)
		goto cleanup;

	opts->retprobe = true;
	skel->links.test_kretprobe_testmod = bpf_program__attach_kprobe_multi_opts(
						skel->progs.test_kretprobe_testmod,
						NULL, opts);
	if (!skel->links.test_kretprobe_testmod)
		goto cleanup;

	ASSERT_OK(trigger_module_test_read(1), "trigger_read");
	kprobe_multi_testmod_check(skel);

cleanup:
	kprobe_multi__destroy(skel);
}

static void test_testmod_attach_api_addrs(void)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	unsigned long long addrs[3];

	addrs[0] = ksym_get_addr_local(ksyms, "bpf_testmod_fentry_test1");
	ASSERT_NEQ(addrs[0], 0, "ksym_get_addr_local");
	addrs[1] = ksym_get_addr_local(ksyms, "bpf_testmod_fentry_test2");
	ASSERT_NEQ(addrs[1], 0, "ksym_get_addr_local");
	addrs[2] = ksym_get_addr_local(ksyms, "bpf_testmod_fentry_test3");
	ASSERT_NEQ(addrs[2], 0, "ksym_get_addr_local");

	opts.addrs = (const unsigned long *) addrs;
	opts.cnt = ARRAY_SIZE(addrs);

	test_testmod_attach_api(&opts);
}

static void test_testmod_attach_api_syms(void)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	const char *syms[3] = {
		"bpf_testmod_fentry_test1",
		"bpf_testmod_fentry_test2",
		"bpf_testmod_fentry_test3",
	};

	opts.syms = syms;
	opts.cnt = ARRAY_SIZE(syms);
	test_testmod_attach_api(&opts);
}

static void test_inline_attach(void)
{
	const char *sym = "bpf_fentry_test_inline";
	struct bpf_link *link = NULL, *fentry_link = NULL;
	struct kprobe_multi_inline *skel = NULL;
	struct bpf_link_info info = {};
	__u32 info_len = sizeof(info);
	int err;

	skel = kprobe_multi_inline__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_inline__open_and_load"))
		return;
	if (skel->kconfig->CONFIG_DEBUG_INFO_BTF_INLINE == TRI_NO) {
		test__skip();
		goto cleanup;
	}

	skel->bss->inline_probe_pid = getpid();
	fentry_link = bpf_program__attach(skel->progs.trigger);
	err = libbpf_get_error(fentry_link);
	if (!ASSERT_OK(err, "attach_trigger")) {
		fentry_link = NULL;
		goto cleanup;
	}
	{
		LIBBPF_OPTS(bpf_kprobe_multi_opts, opts,
			.syms = &sym,
			.cnt = 1,
			.inline_probes = true);

		link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_inline,
							     NULL, &opts);
	}
	err = libbpf_get_error(link);
	if (err == -EOPNOTSUPP) {
		link = NULL;
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_OK(err, "attach_inline_probes")) {
		link = NULL;
		goto cleanup;
	}

	err = bpf_link_get_info_by_fd(bpf_link__fd(link), &info, &info_len);
	if (!ASSERT_OK(err, "get_inline_link_info"))
		goto cleanup;
	ASSERT_EQ(info.kprobe_multi.count, 3, "inline_probe_count_in_link");
	ASSERT_EQ(info.kprobe_multi.flags & BPF_F_KPROBE_MULTI_INLINE,
		  BPF_F_KPROBE_MULTI_INLINE, "inline_probe_flag");

	{
		LIBBPF_OPTS(bpf_test_run_opts, opts);

		ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.trigger),
						 &opts), "trigger_inline_sites");
		ASSERT_EQ(opts.retval, 0, "inline_test_run_retval");
	}
	ASSERT_EQ(skel->bss->inline_probe_count, 3, "inline_probe_hits");

cleanup:
	bpf_link__destroy(link);
	bpf_link__destroy(fentry_link);
	kprobe_multi_inline__destroy(skel);
}

static void test_inline_attach_args(void)
{
	const char *sym = "bpf_fentry_test_inline";
	struct bpf_link *link = NULL, *fentry_link = NULL;
	struct kprobe_multi_inline *skel = NULL;
	int err;

	skel = kprobe_multi_inline__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_inline__open_and_load"))
		return;
	if (skel->kconfig->CONFIG_DEBUG_INFO_BTF_INLINE == TRI_NO) {
		test__skip();
		goto cleanup;
	}

	skel->bss->inline_probe_pid = getpid();
	fentry_link = bpf_program__attach(skel->progs.trigger);
	err = libbpf_get_error(fentry_link);
	if (!ASSERT_OK(err, "attach_trigger")) {
		fentry_link = NULL;
		goto cleanup;
	}
	{
		LIBBPF_OPTS(bpf_kprobe_multi_opts, opts,
			.syms = &sym,
			.cnt = 1,
			.inline_probes = true);

		link = bpf_program__attach_kprobe_multi_opts(
			skel->progs.test_kprobe_inline_args, NULL, &opts);
	}
	err = libbpf_get_error(link);
	if (err == -EOPNOTSUPP) {
		link = NULL;
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_OK(err, "attach_inline_args_probes")) {
		link = NULL;
		goto cleanup;
	}

	{
		LIBBPF_OPTS(bpf_test_run_opts, opts);

		ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.trigger),
						 &opts), "trigger_inline_arg_sites");
		ASSERT_EQ(opts.retval, 0, "inline_args_test_run_retval");
	}
	ASSERT_EQ(skel->bss->inline_args_count, 3, "inline_args_probe_hits");
	ASSERT_EQ(skel->bss->inline_args_mask, 7, "inline_args_all_invocations");
	ASSERT_EQ(skel->bss->inline_args_errors, 0, "inline_args_errors");

cleanup:
	bpf_link__destroy(link);
	bpf_link__destroy(fentry_link);
	kprobe_multi_inline__destroy(skel);
}

static void test_regular_attach_args(void)
{
	const char *sym = "bpf_fentry_test1";
	struct bpf_link *link = NULL, *fentry_link = NULL;
	struct kprobe_multi_inline *skel = NULL;
	int err;

	skel = kprobe_multi_inline__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_inline__open_and_load"))
		return;

	skel->bss->inline_probe_pid = getpid();
	fentry_link = bpf_program__attach(skel->progs.trigger);
	err = libbpf_get_error(fentry_link);
	if (!ASSERT_OK(err, "attach_trigger")) {
		fentry_link = NULL;
		goto cleanup;
	}
	{
		LIBBPF_OPTS(bpf_kprobe_multi_opts, opts,
			.syms = &sym,
			.cnt = 1);

		link = bpf_program__attach_kprobe_multi_opts(
			skel->progs.test_kprobe_multi_regular_args, NULL, &opts);
	}
	err = libbpf_get_error(link);
	if (err == -EOPNOTSUPP) {
		link = NULL;
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_OK(err, "attach_regular_args_probe")) {
		link = NULL;
		goto cleanup;
	}

	{
		LIBBPF_OPTS(bpf_test_run_opts, opts);

		ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.trigger),
						 &opts), "trigger_regular_function");
		ASSERT_EQ(opts.retval, 0, "regular_test_run_retval");
	}
	ASSERT_EQ(skel->bss->regular_args_count, 1, "regular_args_probe_hits");
	ASSERT_EQ(skel->bss->regular_args_errors, 0, "regular_args_errors");

cleanup:
	bpf_link__destroy(link);
	bpf_link__destroy(fentry_link);
	kprobe_multi_inline__destroy(skel);
}

void serial_test_kprobe_multi_testmod_test(void)
{
	ksyms = load_kallsyms_local();
	if (!ASSERT_OK_PTR(ksyms, "load_kallsyms_local"))
		return;

	if (test__start_subtest("testmod_attach_api_syms"))
		test_testmod_attach_api_syms();

	if (test__start_subtest("testmod_attach_api_addrs"))
		test_testmod_attach_api_addrs();

	if (test__start_subtest("inline_attach"))
		test_inline_attach();

	if (test__start_subtest("inline_attach_args"))
		test_inline_attach_args();

	if (test__start_subtest("regular_attach_args"))
		test_regular_attach_args();

	free_kallsyms_local(ksyms);
}

void serial_test_kprobe_multi_inline_scan(void)
{
	struct kprobe_multi_inline *skel = NULL;
	struct inline_func_stat *funcs = NULL;
	struct btf *inline_btf = NULL, *vmlinux_btf = NULL;
	const struct btf_type *func_type, *locsec;
	const struct btf_loc *loc;
	const char *scan = getenv(INLINE_SCAN_ENV);
	unsigned long long text_base;
	__u32 func_cnt = 0, loc_cnt, i, j;
	bool scan_all;
	int locsec_id, err;

	if (!scan || !scan[0]) {
		test__skip();
		return;
	}
	test__force_log();
	scan_all = !strcmp(scan, "all");

	vmlinux_btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(vmlinux_btf);
	if (!ASSERT_OK(err, "load_vmlinux_btf"))
		return;

	inline_btf = btf__parse_split(BTF_INLINE_PATH, vmlinux_btf);
	err = libbpf_get_error(inline_btf);
	if (err == -ENOENT || err == -EOPNOTSUPP) {
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_OK(err, "parse_vmlinux_inline_btf"))
		goto cleanup;

	locsec_id = btf__find_by_name_kind(inline_btf, "inline.text", BTF_KIND_LOCSEC);
	if (locsec_id < 0) {
		test__skip();
		goto cleanup;
	}
	locsec = btf__type_by_id(inline_btf, locsec_id);
	loc_cnt = btf_vlen(locsec);
	funcs = calloc(loc_cnt, sizeof(*funcs));
	if (!ASSERT_OK_PTR(funcs, "alloc_inline_func_stats"))
		goto cleanup;

	for (i = 0, loc = btf_locsec_locs(locsec); i < loc_cnt; i++, loc++) {
		const char *name;

		func_type = btf__type_by_id(inline_btf, loc->func);
		if (!func_type || !btf_is_func(func_type))
			continue;
		name = btf__name_by_offset(inline_btf, func_type->name_off);
		if (!name || (!scan_all && strcmp(name, scan)))
			continue;
		funcs[func_cnt++] = (struct inline_func_stat){
			.name = name,
			.loc_count = 1,
		};
	}
	qsort(funcs, func_cnt, sizeof(*funcs), inline_func_stat_cmp);
	for (i = 0, j = 0; i < func_cnt; i++) {
		if (j && !strcmp(funcs[j - 1].name, funcs[i].name)) {
			funcs[j - 1].loc_count++;
			continue;
		}
		funcs[j++] = funcs[i];
	}
	func_cnt = j;

	skel = kprobe_multi_inline__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_inline__open_and_load"))
		goto cleanup;
	if (skel->kconfig->CONFIG_DEBUG_INFO_BTF_INLINE == TRI_NO) {
		test__skip();
		goto cleanup;
	}
	err = kallsyms_find("_text", &text_base);
	if (!ASSERT_OK(err, "find_text_base") ||
	    !ASSERT_NEQ(text_base, 0, "text_base_nonzero"))
		goto cleanup;

	printf("Inline kprobe attachment scan (" INLINE_SCAN_ENV "=%s)\n", scan);
	printf("%-48s %10s %10s %10s %14s\n", "inline function", "locations",
	       "attached", "error", "attach time (s)");
	for (i = 0; i < func_cnt; i++) {
		const char *sym = funcs[i].name;
		struct bpf_link *link;
		__u64 start_ns;

		LIBBPF_OPTS(bpf_kprobe_multi_opts, opts,
			.syms = &sym,
			.cnt = 1,
			.inline_probes = true);

		start_ns = get_time_ns();
		link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_inline,
							     NULL, &opts);
		funcs[i].attach_time_ns = get_time_ns() - start_ns;
		funcs[i].attach_err = libbpf_get_error(link);
		if (!funcs[i].attach_err)
			bpf_link__destroy(link);
		printf("%-48s %10u %10s %10d %14.6f\n", funcs[i].name,
		       funcs[i].loc_count,
		       funcs[i].attach_err ? "no" : "yes",
		       funcs[i].attach_err,
		       (double)funcs[i].attach_time_ns / 1000000000.0);
	}
	if (!func_cnt && !scan_all)
		printf("%-48s %10u %10s %10d %14.6f\n", scan, 0, "no", -ENOENT, 0.0);

	printf("Locations for %s:\n", scan_all ? "all functions" : scan);
	for (i = 0, loc = btf_locsec_locs(locsec); i < loc_cnt; i++, loc++) {
		const char *name;
		unsigned long long addr;

		func_type = btf__type_by_id(inline_btf, loc->func);
		if (!func_type || !btf_is_func(func_type))
			continue;
		name = btf__name_by_offset(inline_btf, func_type->name_off);
		if (!name || (!scan_all && strcmp(name, scan)))
			continue;
		addr = text_base + loc->offset;
		if (scan_all)
			printf("  %-48s 0x%016llx\n", name, addr);
		else
			printf("  0x%016llx\n", addr);
	}

cleanup:
	free(funcs);
	kprobe_multi_inline__destroy(skel);
	btf__free(inline_btf);
	btf__free(vmlinux_btf);
}
