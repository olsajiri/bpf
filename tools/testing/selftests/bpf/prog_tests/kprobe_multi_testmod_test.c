// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "kprobe_multi.skel.h"
#include "kprobe_multi_inline.skel.h"
#include "trace_helpers.h"
#include "bpf/libbpf_internal.h"

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

	free_kallsyms_local(ksyms);
}
