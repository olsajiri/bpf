// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <sys/prctl.h>
#include <test_progs.h>
#include "kprobe_multi.skel.h"
#include "trace_helpers.h"
#include "kprobe_multi_empty.skel.h"
#include "kprobe_multi_override.skel.h"
#include "kprobe_multi_session.skel.h"
#include "kprobe_multi_session_cookie.skel.h"
#include "kprobe_multi_verifier.skel.h"
#include "kprobe_write_ctx.skel.h"
#include "kprobe_multi_sleepable.skel.h"
#include "kprobe_multi_inline.skel.h"
#include "bpf/libbpf_internal.h"
#include "bpf/hashmap.h"

static void kprobe_multi_test_run(struct kprobe_multi *skel, bool test_return)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err, prog_fd;

	prog_fd = bpf_program__fd(skel->progs.trigger);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel->bss->kprobe_test1_result, 1, "kprobe_test1_result");
	ASSERT_EQ(skel->bss->kprobe_test2_result, 1, "kprobe_test2_result");
	ASSERT_EQ(skel->bss->kprobe_test3_result, 1, "kprobe_test3_result");
	ASSERT_EQ(skel->bss->kprobe_test4_result, 1, "kprobe_test4_result");
	ASSERT_EQ(skel->bss->kprobe_test5_result, 1, "kprobe_test5_result");
	ASSERT_EQ(skel->bss->kprobe_test6_result, 1, "kprobe_test6_result");
	ASSERT_EQ(skel->bss->kprobe_test7_result, 1, "kprobe_test7_result");
	ASSERT_EQ(skel->bss->kprobe_test8_result, 1, "kprobe_test8_result");

	if (test_return) {
		ASSERT_EQ(skel->bss->kretprobe_test1_result, 1, "kretprobe_test1_result");
		ASSERT_EQ(skel->bss->kretprobe_test2_result, 1, "kretprobe_test2_result");
		ASSERT_EQ(skel->bss->kretprobe_test3_result, 1, "kretprobe_test3_result");
		ASSERT_EQ(skel->bss->kretprobe_test4_result, 1, "kretprobe_test4_result");
		ASSERT_EQ(skel->bss->kretprobe_test5_result, 1, "kretprobe_test5_result");
		ASSERT_EQ(skel->bss->kretprobe_test6_result, 1, "kretprobe_test6_result");
		ASSERT_EQ(skel->bss->kretprobe_test7_result, 1, "kretprobe_test7_result");
		ASSERT_EQ(skel->bss->kretprobe_test8_result, 1, "kretprobe_test8_result");
	}
}

static void test_skel_api(void)
{
	struct kprobe_multi *skel = NULL;
	int err;

	skel = kprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi__open_and_load"))
		goto cleanup;

	skel->bss->pid = getpid();
	err = kprobe_multi__attach(skel);
	if (!ASSERT_OK(err, "kprobe_multi__attach"))
		goto cleanup;

	kprobe_multi_test_run(skel, true);

cleanup:
	kprobe_multi__destroy(skel);
}

static void test_link_api(struct bpf_link_create_opts *opts)
{
	int prog_fd, link1_fd = -1, link2_fd = -1;
	struct kprobe_multi *skel = NULL;

	skel = kprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_raw_skel_load"))
		goto cleanup;

	skel->bss->pid = getpid();
	prog_fd = bpf_program__fd(skel->progs.test_kprobe);
	link1_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_KPROBE_MULTI, opts);
	if (!ASSERT_GE(link1_fd, 0, "link_fd"))
		goto cleanup;

	opts->kprobe_multi.flags = BPF_F_KPROBE_MULTI_RETURN;
	prog_fd = bpf_program__fd(skel->progs.test_kretprobe);
	link2_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_KPROBE_MULTI, opts);
	if (!ASSERT_GE(link2_fd, 0, "link_fd"))
		goto cleanup;

	kprobe_multi_test_run(skel, true);

cleanup:
	if (link1_fd != -1)
		close(link1_fd);
	if (link2_fd != -1)
		close(link2_fd);
	kprobe_multi__destroy(skel);
}

#define GET_ADDR(__sym, __addr) ({					\
	__addr = ksym_get_addr(__sym);					\
	if (!ASSERT_NEQ(__addr, 0, "kallsyms load failed for " #__sym))	\
		return;							\
})

static void test_link_api_addrs(void)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts);
	unsigned long long addrs[8];

	GET_ADDR("bpf_fentry_test1", addrs[0]);
	GET_ADDR("bpf_fentry_test2", addrs[1]);
	GET_ADDR("bpf_fentry_test3", addrs[2]);
	GET_ADDR("bpf_fentry_test4", addrs[3]);
	GET_ADDR("bpf_fentry_test5", addrs[4]);
	GET_ADDR("bpf_fentry_test6", addrs[5]);
	GET_ADDR("bpf_fentry_test7", addrs[6]);
	GET_ADDR("bpf_fentry_test8", addrs[7]);

	opts.kprobe_multi.addrs = (const unsigned long*) addrs;
	opts.kprobe_multi.cnt = ARRAY_SIZE(addrs);
	test_link_api(&opts);
}

static void test_link_api_syms(void)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts);
	const char *syms[8] = {
		"bpf_fentry_test1",
		"bpf_fentry_test2",
		"bpf_fentry_test3",
		"bpf_fentry_test4",
		"bpf_fentry_test5",
		"bpf_fentry_test6",
		"bpf_fentry_test7",
		"bpf_fentry_test8",
	};

	opts.kprobe_multi.syms = syms;
	opts.kprobe_multi.cnt = ARRAY_SIZE(syms);
	test_link_api(&opts);
}

static void
test_attach_api(const char *pattern, struct bpf_kprobe_multi_opts *opts)
{
	struct bpf_link *link1 = NULL, *link2 = NULL;
	struct kprobe_multi *skel = NULL;

	skel = kprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_raw_skel_load"))
		goto cleanup;

	skel->bss->pid = getpid();
	link1 = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_manual,
						      pattern, opts);
	if (!ASSERT_OK_PTR(link1, "bpf_program__attach_kprobe_multi_opts"))
		goto cleanup;

	if (opts) {
		opts->retprobe = true;
		link2 = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kretprobe_manual,
							      pattern, opts);
		if (!ASSERT_OK_PTR(link2, "bpf_program__attach_kprobe_multi_opts"))
			goto cleanup;
	}

	kprobe_multi_test_run(skel, !!opts);

cleanup:
	bpf_link__destroy(link2);
	bpf_link__destroy(link1);
	kprobe_multi__destroy(skel);
}

static void test_attach_api_pattern(void)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);

	test_attach_api("bpf_fentry_test*", &opts);
	test_attach_api("bpf_fentry_test?", NULL);
}

static void test_attach_api_addrs(void)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	unsigned long long addrs[8];

	GET_ADDR("bpf_fentry_test1", addrs[0]);
	GET_ADDR("bpf_fentry_test2", addrs[1]);
	GET_ADDR("bpf_fentry_test3", addrs[2]);
	GET_ADDR("bpf_fentry_test4", addrs[3]);
	GET_ADDR("bpf_fentry_test5", addrs[4]);
	GET_ADDR("bpf_fentry_test6", addrs[5]);
	GET_ADDR("bpf_fentry_test7", addrs[6]);
	GET_ADDR("bpf_fentry_test8", addrs[7]);

	opts.addrs = (const unsigned long *) addrs;
	opts.cnt = ARRAY_SIZE(addrs);
	test_attach_api(NULL, &opts);
}

static void test_attach_api_syms(void)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	const char *syms[8] = {
		"bpf_fentry_test1",
		"bpf_fentry_test2",
		"bpf_fentry_test3",
		"bpf_fentry_test4",
		"bpf_fentry_test5",
		"bpf_fentry_test6",
		"bpf_fentry_test7",
		"bpf_fentry_test8",
	};

	opts.syms = syms;
	opts.cnt = ARRAY_SIZE(syms);
	test_attach_api(NULL, &opts);
}

static void test_attach_api_fails(void)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct kprobe_multi *skel = NULL;
	struct kprobe_multi_sleepable *sl_skel = NULL;
	struct bpf_link *link = NULL;
	unsigned long long addrs[2];
	const char *syms[2] = {
		"bpf_fentry_test1",
		"bpf_fentry_test2",
	};
	__u64 cookies[2];
	int saved_error, err;

	addrs[0] = ksym_get_addr("bpf_fentry_test1");
	addrs[1] = ksym_get_addr("bpf_fentry_test2");

	if (!ASSERT_FALSE(!addrs[0] || !addrs[1], "ksym_get_addr"))
		goto cleanup;

	skel = kprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_raw_skel_load"))
		goto cleanup;

	skel->bss->pid = getpid();

	/* fail_1 - pattern and opts NULL */
	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_manual,
						     NULL, NULL);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "fail_1"))
		goto cleanup;

	if (!ASSERT_EQ(saved_error, -EINVAL, "fail_1_error"))
		goto cleanup;

	/* fail_2 - both addrs and syms set */
	opts.addrs = (const unsigned long *) addrs;
	opts.syms = syms;
	opts.cnt = ARRAY_SIZE(syms);
	opts.cookies = NULL;

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_manual,
						     NULL, &opts);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "fail_2"))
		goto cleanup;

	if (!ASSERT_EQ(saved_error, -EINVAL, "fail_2_error"))
		goto cleanup;

	/* fail_3 - pattern and addrs set */
	opts.addrs = (const unsigned long *) addrs;
	opts.syms = NULL;
	opts.cnt = ARRAY_SIZE(syms);
	opts.cookies = NULL;

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_manual,
						     "ksys_*", &opts);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "fail_3"))
		goto cleanup;

	if (!ASSERT_EQ(saved_error, -EINVAL, "fail_3_error"))
		goto cleanup;

	/* fail_4 - pattern and cnt set */
	opts.addrs = NULL;
	opts.syms = NULL;
	opts.cnt = ARRAY_SIZE(syms);
	opts.cookies = NULL;

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_manual,
						     "ksys_*", &opts);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "fail_4"))
		goto cleanup;

	if (!ASSERT_EQ(saved_error, -EINVAL, "fail_4_error"))
		goto cleanup;

	/* fail_5 - pattern and cookies */
	opts.addrs = NULL;
	opts.syms = NULL;
	opts.cnt = 0;
	opts.cookies = cookies;

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_manual,
						     "ksys_*", &opts);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "fail_5"))
		goto cleanup;

	if (!ASSERT_EQ(saved_error, -EINVAL, "fail_5_error"))
		goto cleanup;

	/* fail_6 - abnormal cnt */
	opts.addrs = (const unsigned long *) addrs;
	opts.syms = NULL;
	opts.cnt = INT_MAX;
	opts.cookies = NULL;

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_manual,
						     NULL, &opts);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "fail_6"))
		goto cleanup;

	if (!ASSERT_EQ(saved_error, -E2BIG, "fail_6_error"))
		goto cleanup;

	/* fail_7 - non-existent wildcard pattern (slow path) */
	LIBBPF_OPTS_RESET(opts);

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_manual,
						     "__nonexistent_func_xyz_*",
						     &opts);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "fail_7"))
		goto cleanup;

	if (!ASSERT_EQ(saved_error, -ENOENT, "fail_7_error"))
		goto cleanup;

	/* fail_8 - non-existent exact name (fast path), same error as wildcard */
	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_manual,
						     "__nonexistent_func_xyz_123",
						     &opts);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "fail_8"))
		goto cleanup;

	if (!ASSERT_EQ(saved_error, -ENOENT, "fail_8_error"))
		goto cleanup;

	/* fail_9 - sleepable kprobe multi should not attach */
	sl_skel = kprobe_multi_sleepable__open();
	if (!ASSERT_OK_PTR(sl_skel, "sleep_skel_open"))
		goto cleanup;

	sl_skel->bss->user_ptr = sl_skel;

	err = bpf_program__add_flags(sl_skel->progs.handle_kprobe_multi_sleepable, BPF_F_SLEEPABLE);
	if (!ASSERT_OK(err, "sleep_skel_set_flags"))
		goto cleanup;

	err = kprobe_multi_sleepable__load(sl_skel);
	if (!ASSERT_OK(err, "sleep_skel_load"))
		goto cleanup;

	link = bpf_program__attach_kprobe_multi_opts(sl_skel->progs.handle_kprobe_multi_sleepable,
						     "bpf_fentry_test1", NULL);
	saved_error = -errno;

	if (!ASSERT_ERR_PTR(link, "fail_9"))
		goto cleanup;

	if (!ASSERT_EQ(saved_error, -EINVAL, "fail_9_error"))
		goto cleanup;

	err = bpf_prog_test_run_opts(bpf_program__fd(sl_skel->progs.fentry), &topts);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

cleanup:
	bpf_link__destroy(link);
	kprobe_multi__destroy(skel);
	kprobe_multi_sleepable__destroy(sl_skel);
}

static void test_session_skel_api(void)
{
	struct kprobe_multi_session *skel = NULL;
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_link *link = NULL;
	int i, err, prog_fd;

	skel = kprobe_multi_session__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_session__open_and_load"))
		return;

	skel->bss->pid = getpid();

	err = kprobe_multi_session__attach(skel);
	if (!ASSERT_OK(err, " kprobe_multi_session__attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.trigger);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	/*
	 * bpf_fentry_test1 is hit by both the wildcard probe and the exact
	 * name probe (test_kprobe_syms), so entry + return fires twice: 4.
	 * bpf_fentry_test2-4 are hit only by the wildcard probe: 2.
	 */
	ASSERT_EQ(skel->bss->kprobe_session_result[0], 4, "kprobe_session_result");
	for (i = 1; i < 4; i++)
		ASSERT_EQ(skel->bss->kprobe_session_result[i], 2, "kprobe_session_result");

	/* bpf_fentry_test5-8 trigger only entry probe, result is 1 */
	for (i = 4; i < 8; i++)
		ASSERT_EQ(skel->bss->kprobe_session_result[i], 1, "kprobe_session_result");

cleanup:
	bpf_link__destroy(link);
	kprobe_multi_session__destroy(skel);
}

static void test_session_cookie_skel_api(void)
{
	struct kprobe_multi_session_cookie *skel = NULL;
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_link *link = NULL;
	int err, prog_fd;

	skel = kprobe_multi_session_cookie__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_raw_skel_load"))
		return;

	skel->bss->pid = getpid();

	err = kprobe_multi_session_cookie__attach(skel);
	if (!ASSERT_OK(err, " kprobe_multi_wrapper__attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.trigger);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test_kprobe_1_result, 1, "test_kprobe_1_result");
	ASSERT_EQ(skel->bss->test_kprobe_2_result, 2, "test_kprobe_2_result");
	ASSERT_EQ(skel->bss->test_kprobe_3_result, 3, "test_kprobe_3_result");

cleanup:
	bpf_link__destroy(link);
	kprobe_multi_session_cookie__destroy(skel);
}

static void test_unique_match(void)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	struct kprobe_multi *skel = NULL;
	struct bpf_link *link = NULL;

	skel = kprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi__open_and_load"))
		return;

	opts.unique_match = true;
	skel->bss->pid = getpid();
	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_manual,
						     "bpf_fentry_test*", &opts);
	if (!ASSERT_ERR_PTR(link, "bpf_program__attach_kprobe_multi_opts"))
		bpf_link__destroy(link);

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_manual,
						     "bpf_fentry_test8*", &opts);
	if (ASSERT_OK_PTR(link, "bpf_program__attach_kprobe_multi_opts"))
		bpf_link__destroy(link);

	kprobe_multi__destroy(skel);
}

/* Get value of the @name counter from fdinfo of kprobe multi link. */
static long get_fdinfo_cnt(int link_fd, const char *name)
{
	char path[64], buf[256], fmt[64];
	long cnt = -1;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", link_fd);
	f = fopen(path, "r");
	if (!ASSERT_OK_PTR(f, "open_fdinfo"))
		return -1;

	snprintf(fmt, sizeof(fmt), "%s:\t%%ld", name);
	while (fgets(buf, sizeof(buf), f)) {
		if (sscanf(buf, fmt, &cnt) == 1)
			break;
	}
	fclose(f);
	return cnt;
}

static void do_bench_test(struct kprobe_multi_empty *skel, struct bpf_kprobe_multi_opts *opts)
{
	long attach_start_ns, attach_end_ns;
	long detach_start_ns, detach_end_ns;
	double attach_delta, detach_delta;
	struct bpf_link *link = NULL;

	attach_start_ns = get_time_ns();
	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_empty,
						     NULL, opts);
	attach_end_ns = get_time_ns();

	if (!ASSERT_OK_PTR(link, "bpf_program__attach_kprobe_multi_opts"))
		return;

	detach_start_ns = get_time_ns();
	bpf_link__destroy(link);
	detach_end_ns = get_time_ns();

	attach_delta = (attach_end_ns - attach_start_ns) / 1000000000.0;
	detach_delta = (detach_end_ns - detach_start_ns) / 1000000000.0;

	printf("%s: found %lu functions\n", __func__, opts->cnt);
	printf("%s: attached in %7.3lfs\n", __func__, attach_delta);
	printf("%s: detached in %7.3lfs\n", __func__, detach_delta);
}

static void test_kprobe_multi_bench_attach(bool kernel)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	struct kprobe_multi_empty *skel = NULL;
	struct ksyms *ksyms = NULL;

	if (!ASSERT_OK(bpf_get_ksyms(&ksyms, kernel), "bpf_get_ksyms"))
		return;

	skel = kprobe_multi_empty__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_empty__open_and_load"))
		goto cleanup;

	opts.syms = (const char **)ksyms->filtered_syms;
	opts.cnt = ksyms->filtered_cnt;

	do_bench_test(skel, &opts);

cleanup:
	kprobe_multi_empty__destroy(skel);
	free_kallsyms_local(ksyms);
}

static void test_kprobe_multi_bench_attach_addr(bool kernel)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	struct kprobe_multi_empty *skel = NULL;
	unsigned long *addrs = NULL;
	size_t cnt = 0;
	int err;

	err = bpf_get_addrs(&addrs, &cnt, kernel);
	if (err == -ENOENT) {
		test__skip();
		return;
	}

	if (!ASSERT_OK(err, "bpf_get_addrs"))
		return;

	skel = kprobe_multi_empty__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_empty__open_and_load"))
		goto cleanup;

	opts.addrs = addrs;
	opts.cnt = cnt;

	do_bench_test(skel, &opts);

cleanup:
	kprobe_multi_empty__destroy(skel);
	free(addrs);
}

static void test_attach_override(void)
{
	struct kprobe_multi_override *skel = NULL;
	struct bpf_link *link = NULL;

	skel = kprobe_multi_override__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_empty__open_and_load"))
		goto cleanup;

	/* The test_override calls bpf_override_return so it should fail
	 * to attach to bpf_fentry_test1 function, which is not on error
	 * injection list.
	 */
	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_override,
						     "bpf_fentry_test1", NULL);
	if (!ASSERT_ERR_PTR(link, "override_attached_bpf_fentry_test1")) {
		bpf_link__destroy(link);
		goto cleanup;
	}

	/* The should_fail_bio function is on error injection list,
	 * attach should succeed.
	 */
	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_override,
						     "should_fail_bio", NULL);
	if (!ASSERT_OK_PTR(link, "override_attached_should_fail_bio"))
		goto cleanup;

	bpf_link__destroy(link);

cleanup:
	kprobe_multi_override__destroy(skel);
}

static void test_override(void)
{
	struct kprobe_multi_override *skel = NULL;
	int err;

	skel = kprobe_multi_override__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_empty__open_and_load"))
		goto cleanup;

	skel->bss->pid = getpid();

	/* no override */
	err = prctl(0xffff, 0);
	ASSERT_EQ(err, -1, "err");

	/* kprobe.multi override */
	skel->links.test_override = bpf_program__attach_kprobe_multi_opts(skel->progs.test_override,
						SYS_PREFIX "sys_prctl", NULL);
	if (!ASSERT_OK_PTR(skel->links.test_override, "bpf_program__attach_kprobe_multi_opts"))
		goto cleanup;

	err = prctl(0xffff, 0);
	ASSERT_EQ(err, 123, "err");

	bpf_link__destroy(skel->links.test_override);
	skel->links.test_override = NULL;

	/* kprobe override */
	skel->links.test_kprobe_override = bpf_program__attach_kprobe(skel->progs.test_kprobe_override,
							false, SYS_PREFIX "sys_prctl");
	if (!ASSERT_OK_PTR(skel->links.test_kprobe_override, "bpf_program__attach_kprobe"))
		goto cleanup;

	err = prctl(0xffff, 0);
	ASSERT_EQ(err, 123, "err");

cleanup:
	kprobe_multi_override__destroy(skel);
}

#ifdef __x86_64__
static void test_attach_write_ctx(void)
{
	struct kprobe_write_ctx *skel = NULL;
	struct bpf_link *link = NULL;

	skel = kprobe_write_ctx__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_write_ctx__open_and_load"))
		return;

	link = bpf_program__attach_kprobe_opts(skel->progs.kprobe_multi_write_ctx,
						     "bpf_fentry_test1", NULL);
	if (!ASSERT_ERR_PTR(link, "bpf_program__attach_kprobe_opts"))
		bpf_link__destroy(link);

	kprobe_write_ctx__destroy(skel);
}
#else
static void test_attach_write_ctx(void)
{
	test__skip();
}
#endif

/*
 * Test kprobe_multi handles shadow symbols (vmlinux + module duplicate).
 * bpf_fentry_shadow_test exists in both vmlinux and bpf_testmod.
 * kprobe_multi resolves via ftrace_lookup_symbols() which finds the
 * vmlinux symbol first and stops, so this should always succeed.
 */
static void test_attach_probe_dup_sym(void)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	const char *syms[1] = { "bpf_fentry_shadow_test" };
	struct kprobe_multi *skel = NULL;
	struct bpf_link *link1 = NULL, *link2 = NULL;

	skel = kprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi__open_and_load"))
		goto cleanup;

	skel->bss->pid = getpid();
	opts.syms = syms;
	opts.cnt = ARRAY_SIZE(syms);

	link1 = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_manual,
						      NULL, &opts);
	if (!ASSERT_OK_PTR(link1, "attach_kprobe_multi_dup_sym"))
		goto cleanup;

	opts.retprobe = true;
	link2 = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kretprobe_manual,
						      NULL, &opts);
	if (!ASSERT_OK_PTR(link2, "attach_kretprobe_multi_dup_sym"))
		goto cleanup;

cleanup:
	bpf_link__destroy(link2);
	bpf_link__destroy(link1);
	kprobe_multi__destroy(skel);
}

#define INLINE_INNER	"bpf_kprobe_multi_inline_inner"
#define INLINE_OUTER	"bpf_kprobe_multi_inline_outer"
#define INLINE_CALLER	"bpf_kprobe_multi_inline_test"
#define INLINE_MAX	8

/*
 * Get addresses of inlined instances of @func from inline.text LOCSEC
 * of @inline_btf, the offsets are relative to @base. Returns number of
 * instances or -ENOENT if there's no such LOCSEC.
 */
static int find_inline_sites(struct btf *inline_btf, unsigned long base, const char *func,
			     unsigned long *addrs, int max)
{
	const struct btf_type *t, *ft;
	struct btf_loc *l;
	int id, i, n, cnt = 0;

	id = btf__find_by_name_kind(inline_btf, "inline.text", BTF_KIND_LOCSEC);
	if (id < 0)
		return -ENOENT;

	t = btf__type_by_id(inline_btf, id);
	n = btf_vlen(t);
	for (i = 0, l = btf_locsec_locs(t); i < n; i++, l++) {
		ft = btf__type_by_id(inline_btf, l->func);
		if (!ft || strcmp(btf__name_by_offset(inline_btf, ft->name_off), func))
			continue;
		if (!ASSERT_LT(cnt, max, "inline_sites_max"))
			return -EINVAL;
		addrs[cnt++] = base + l->offset;
	}
	return cnt;
}

/*
 * Get addresses of inlined instances of @func from vmlinux inline BTF.
 * Returns number of instances or -ENOENT if there's no inline BTF.
 */
static int get_inline_sites(const char *func, unsigned long *addrs, int max)
{
	struct btf *vmlinux_btf, *inline_btf = NULL;
	unsigned long base;
	int cnt = 0;

	/* LOCSEC offsets are relative to the .text section base. */
	base = ksym_get_addr("_stext");
	if (!ASSERT_NEQ(base, 0, "stext_addr"))
		return -EINVAL;

	vmlinux_btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(vmlinux_btf, "vmlinux_btf"))
		return -EINVAL;

	inline_btf = btf__parse_split("/sys/kernel/btf/vmlinux.inline", vmlinux_btf);
	cnt = libbpf_get_error(inline_btf);
	if (cnt) {
		inline_btf = NULL;
		/* pahole may not have inline BTF feature support. */
		if (cnt != -ENOENT)
			ASSERT_OK(cnt, "parse_inline_btf");
		goto out;
	}

	cnt = find_inline_sites(inline_btf, base, func, addrs, max);
out:
	btf__free(inline_btf);
	btf__free(vmlinux_btf);
	return cnt;
}

/*
 * Get addresses of inlined instances of @func from bpf_testmod inline BTF.
 * Returns number of instances or -ENOENT if there's no inline BTF.
 */
static int get_testmod_inline_sites(const char *func, unsigned long *addrs, int max)
{
	struct btf *vmlinux_btf, *mod_btf = NULL, *inline_btf = NULL;
	unsigned long base = 0;
	int cnt = -EINVAL;
	FILE *f;

	/* LOCSEC offsets are relative to the module .text section base. */
	f = fopen("/sys/module/bpf_testmod/sections/.text", "r");
	if (!ASSERT_OK_PTR(f, "testmod_text"))
		return -EINVAL;
	if (fscanf(f, "%lx", &base) != 1)
		base = 0;
	fclose(f);
	if (!ASSERT_NEQ(base, 0, "testmod_text_addr"))
		return -EINVAL;

	vmlinux_btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(vmlinux_btf, "vmlinux_btf"))
		return -EINVAL;

	mod_btf = btf__parse_split("/sys/kernel/btf/bpf_testmod", vmlinux_btf);
	if (!ASSERT_OK_PTR(mod_btf, "testmod_btf")) {
		mod_btf = NULL;
		goto out;
	}

	inline_btf = btf__parse_split("/sys/kernel/btf/bpf_testmod.inline", mod_btf);
	cnt = libbpf_get_error(inline_btf);
	if (cnt) {
		inline_btf = NULL;
		/* pahole may not have inline BTF feature support. */
		if (cnt != -ENOENT)
			ASSERT_OK(cnt, "parse_testmod_inline_btf");
		goto out;
	}

	cnt = find_inline_sites(inline_btf, base, func, addrs, max);
out:
	btf__free(inline_btf);
	btf__free(mod_btf);
	btf__free(vmlinux_btf);
	return cnt;
}

static int inline_hits(struct kprobe_multi_inline *skel, unsigned long ip, __u64 cookie)
{
	int i, cnt = 0;

	for (i = 0; i < skel->bss->hits_cnt; i++) {
		if (skel->bss->hits_ip[i] == ip && skel->bss->hits_cookie[i] == cookie)
			cnt++;
	}
	return cnt;
}

static void inline_trigger(struct kprobe_multi_inline *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err;

	skel->bss->hits_cnt = 0;
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.trigger), &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");
}

/* Each inlined instance must be hit just once with its function cookie. */
static void inline_check_sites(struct kprobe_multi_inline *skel, unsigned long *addrs,
			       int cnt, __u64 cookie)
{
	struct ksym *ksym;
	int i;

	for (i = 0; i < cnt; i++) {
		ASSERT_EQ(inline_hits(skel, addrs[i], cookie), 1, "inline_site_hit");

		/* And it needs to be located in one of the callers. */
		ksym = ksym_search(addrs[i]);
		if (!ASSERT_OK_PTR(ksym, "ksym_search"))
			continue;
		ASSERT_OK(strncmp(ksym->name, INLINE_CALLER, strlen(INLINE_CALLER)),
			  "inline_site_caller");
	}
}

static void test_inline(bool same_addr)
{
	unsigned long inner[INLINE_MAX], outer[INLINE_MAX];
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	const char *syms[2] = { INLINE_OUTER, INLINE_INNER };
	__u64 cookies[2] = { 2, 1 };
	struct kprobe_multi_inline *skel = NULL;
	struct bpf_link *link = NULL;
	int inner_cnt, outer_cnt, i;
	bool shared = false;

	inner_cnt = get_inline_sites(INLINE_INNER, inner, INLINE_MAX);
	outer_cnt = get_inline_sites(INLINE_OUTER, outer, INLINE_MAX);
	if (inner_cnt == -ENOENT || outer_cnt == -ENOENT) {
		test__skip();
		return;
	}

	/* inner is inlined in both callers, outer just in the first one */
	if (!ASSERT_EQ(inner_cnt, 2, "inner_cnt") || !ASSERT_EQ(outer_cnt, 1, "outer_cnt"))
		return;

	for (i = 0; i < inner_cnt; i++)
		shared |= inner[i] == outer[0];

	/* Compiler did not place inner and outer instances on same address. */
	if (same_addr && !shared) {
		test__skip();
		return;
	}

	skel = kprobe_multi_inline__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_inline__open_and_load"))
		return;

	skel->bss->pid = getpid();

	opts.syms = syms;
	opts.cookies = cookies;
	opts.cnt = ARRAY_SIZE(syms);
	opts.inlined = true;

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_inline,
						     NULL, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_kprobe_multi_opts"))
		goto cleanup;

	inline_trigger(skel);

	ASSERT_EQ(skel->bss->hits_cnt, inner_cnt + outer_cnt, "hits_cnt");
	inline_check_sites(skel, inner, inner_cnt, 1);
	inline_check_sites(skel, outer, outer_cnt, 2);

	if (same_addr) {
		/* Both instances on the same address got their own cookie. */
		ASSERT_EQ(inline_hits(skel, outer[0], 1), 1, "same_addr_inner");
		ASSERT_EQ(inline_hits(skel, outer[0], 2), 1, "same_addr_outer");
	}

	/* Make sure the probes are gone after detach. */
	bpf_link__destroy(link);
	link = NULL;

	inline_trigger(skel);
	ASSERT_EQ(skel->bss->hits_cnt, 0, "hits_cnt_detached");

cleanup:
	bpf_link__destroy(link);
	kprobe_multi_inline__destroy(skel);
}

/* Attach function with entry probe and inlined function in single link. */
static void test_inline_mixed(void)
{
	const char *syms[2] = { INLINE_INNER, "bpf_fentry_test1" };
	LIBBPF_OPTS(bpf_link_create_opts, opts);
	struct kprobe_multi_inline *skel = NULL;
	unsigned long inner[INLINE_MAX], addr;
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);
	__u64 cookies[2] = { 6, 5 };
	int inner_cnt, link_fd = -1, err;

	inner_cnt = get_inline_sites(INLINE_INNER, inner, INLINE_MAX);
	if (inner_cnt == -ENOENT) {
		test__skip();
		return;
	}
	if (!ASSERT_EQ(inner_cnt, 2, "inner_cnt"))
		return;

	addr = ksym_get_addr("bpf_fentry_test1");
	if (!ASSERT_NEQ(addr, 0, "bpf_fentry_test1_addr"))
		return;

	skel = kprobe_multi_inline__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_inline__open_and_load"))
		return;

	skel->bss->pid = getpid();

	opts.kprobe_multi.syms = syms;
	opts.kprobe_multi.cookies = cookies;
	opts.kprobe_multi.cnt = ARRAY_SIZE(syms);
	opts.kprobe_multi.flags = BPF_F_KPROBE_MULTI_INLINE;

	link_fd = bpf_link_create(bpf_program__fd(skel->progs.test_kprobe_inline), 0,
				  BPF_TRACE_KPROBE_MULTI, &opts);
	if (!ASSERT_GE(link_fd, 0, "bpf_link_create"))
		goto cleanup;

	inline_trigger(skel);

	ASSERT_EQ(skel->bss->hits_cnt, inner_cnt + 1, "hits_cnt");
	ASSERT_EQ(inline_hits(skel, addr, 5), 1, "entry_hit");
	inline_check_sites(skel, inner, inner_cnt, 6);

	/* Link info shows only the function with entry probe. */
	err = bpf_link_get_info_by_fd(link_fd, &info, &len);
	if (!ASSERT_OK(err, "bpf_link_get_info_by_fd"))
		goto cleanup;
	ASSERT_EQ(info.type, BPF_LINK_TYPE_KPROBE_MULTI, "info_type");
	ASSERT_EQ(info.kprobe_multi.count, 1, "info_count");
	ASSERT_EQ(info.kprobe_multi.flags, BPF_F_KPROBE_MULTI_INLINE, "info_flags");

cleanup:
	if (link_fd >= 0)
		close(link_fd);
	kprobe_multi_inline__destroy(skel);
}

#define INLINE_PARTIAL		"bpf_kprobe_multi_inline_partial"
#define INLINE_PARTIAL_CALLER	"bpf_kprobe_multi_inline_test3"
#define INLINE_NOKPROBE		"bpf_kprobe_multi_inline_nokprobe"

/* Inlined instances that can't be attached are skipped. */
static void test_inline_skip(void)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	const char *syms[1] = { INLINE_PARTIAL };
	const char *nosyms[1] = { INLINE_NOKPROBE };
	struct kprobe_multi_inline *skel = NULL;
	unsigned long sites[INLINE_MAX];
	struct bpf_link *link = NULL;
	__u64 cookies[1] = { 8 };
	int cnt, i, saved_error;
	struct ksym *ksym;
	bool attached;

	cnt = get_inline_sites(INLINE_PARTIAL, sites, INLINE_MAX);
	if (cnt == -ENOENT) {
		test__skip();
		return;
	}

	/* One instance in function that kprobes can attach and one that can't. */
	if (!ASSERT_EQ(cnt, 2, "inline_sites_cnt"))
		return;

	skel = kprobe_multi_inline__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_inline__open_and_load"))
		return;

	skel->bss->pid = getpid();

	opts.syms = syms;
	opts.cookies = cookies;
	opts.cnt = ARRAY_SIZE(syms);
	opts.inlined = true;

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_inline,
						     NULL, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_kprobe_multi_opts"))
		goto cleanup;

	ASSERT_EQ(get_fdinfo_cnt(bpf_link__fd(link), "kprobe_inline_cnt"), 1,
		  "kprobe_inline_cnt");
	ASSERT_EQ(get_fdinfo_cnt(bpf_link__fd(link), "kprobe_inline_skipped"), 1,
		  "kprobe_inline_skipped");

	inline_trigger(skel);

	/* Only the instance outside of the nokprobe function is hit. */
	ASSERT_EQ(skel->bss->hits_cnt, 1, "hits_cnt");

	for (i = 0; i < cnt; i++) {
		ksym = ksym_search(sites[i]);
		if (!ASSERT_OK_PTR(ksym, "ksym_search"))
			continue;
		attached = !strcmp(ksym->name, INLINE_PARTIAL_CALLER);
		ASSERT_EQ(inline_hits(skel, sites[i], 8), attached ? 1 : 0, "inline_site_hit");
	}

	bpf_link__destroy(link);

	/* Function with no entry and all inlined instances skipped fails to attach. */
	opts.syms = nosyms;
	opts.cookies = NULL;

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_inline,
						     NULL, &opts);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "attach_nokprobe"))
		goto cleanup;
	link = NULL;
	ASSERT_EQ(saved_error, -EINVAL, "attach_nokprobe_error");

cleanup:
	bpf_link__destroy(link);
	kprobe_multi_inline__destroy(skel);
}

#define TESTMOD_INLINE		"bpf_testmod_kprobe_multi_inline"
#define TESTMOD_INLINE_CALLER	"bpf_testmod_kprobe_multi_inline_test"

/* Attach inlined function in kernel module. */
static void test_inline_module(void)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	const char *syms[1] = { TESTMOD_INLINE };
	struct kprobe_multi_inline *skel = NULL;
	struct bpf_link *link = NULL;
	unsigned long sites[INLINE_MAX];
	__u64 cookies[1] = { 7 };
	struct ksym *ksym;
	int cnt;

	cnt = get_testmod_inline_sites(TESTMOD_INLINE, sites, INLINE_MAX);
	if (cnt == -ENOENT) {
		test__skip();
		return;
	}
	if (!ASSERT_EQ(cnt, 1, "sites_cnt"))
		return;

	ksym = ksym_search(sites[0]);
	if (!ASSERT_OK_PTR(ksym, "ksym_search"))
		return;
	ASSERT_STREQ(ksym->name, TESTMOD_INLINE_CALLER, "inline_site_caller");

	skel = kprobe_multi_inline__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_inline__open_and_load"))
		return;

	skel->bss->pid = getpid();

	opts.syms = syms;
	opts.cookies = cookies;
	opts.cnt = ARRAY_SIZE(syms);
	opts.inlined = true;

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_inline,
						     NULL, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_kprobe_multi_opts"))
		goto cleanup;

	skel->bss->hits_cnt = 0;
	ASSERT_OK(trigger_module_test_read(1), "trigger_read");

	ASSERT_EQ(skel->bss->hits_cnt, 1, "hits_cnt");
	ASSERT_EQ(inline_hits(skel, sites[0], 7), 1, "inline_site_hit");

	/* Make sure the probe is gone after detach. */
	bpf_link__destroy(link);
	link = NULL;

	skel->bss->hits_cnt = 0;
	ASSERT_OK(trigger_module_test_read(1), "trigger_read");
	ASSERT_EQ(skel->bss->hits_cnt, 0, "hits_cnt_detached");

cleanup:
	bpf_link__destroy(link);
	kprobe_multi_inline__destroy(skel);
}

/*
 * Make sure the link create fails with @error and kernel explains
 * the failure with @msg in the log.
 */
static bool inline_link_fails(int prog_fd, enum bpf_attach_type type,
			      struct bpf_link_create_opts *lopts,
			      int error, const char *msg)
{
	LIBBPF_OPTS(bpf_log_opts, log_opts);
	char log_buf[4096] = {};
	int saved_error, link_fd;

	log_opts.buf = log_buf;
	log_opts.size = sizeof(log_buf);
	log_opts.level = 1;
	lopts->log_opts = &log_opts;

	link_fd = bpf_link_create(prog_fd, 0, type, lopts);
	saved_error = -errno;
	if (!ASSERT_LT(link_fd, 0, "link_create")) {
		close(link_fd);
		return false;
	}
	ASSERT_EQ(saved_error, error, "link_create_error");
	ASSERT_HAS_SUBSTR(log_buf, msg, "link_create_log");
	return true;
}

static void test_inline_fails(void)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	LIBBPF_OPTS(bpf_link_create_opts, lopts);
	struct kprobe_multi_inline *skel = NULL;
	const char *syms[1] = { INLINE_INNER };
	const char *nosyms[1] = { "bpf_kprobe_multi_inline_nonexistent" };
	const char *nokprobe[1] = { INLINE_NOKPROBE };
	unsigned long inner[INLINE_MAX], addrs[1];
	int saved_error, prog_fd;
	struct bpf_link *link = NULL;

	if (get_inline_sites(INLINE_INNER, inner, INLINE_MAX) == -ENOENT) {
		test__skip();
		return;
	}

	addrs[0] = ksym_get_addr("bpf_fentry_test1");
	if (!ASSERT_NEQ(addrs[0], 0, "bpf_fentry_test1_addr"))
		return;

	skel = kprobe_multi_inline__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_inline__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.test_kprobe_inline);

	/* fail_1 - inlined with addrs */
	opts.addrs = addrs;
	opts.cnt = 1;
	opts.inlined = true;

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_inline,
						     NULL, &opts);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "fail_1"))
		goto cleanup;
	ASSERT_EQ(saved_error, -EINVAL, "fail_1_error");

	lopts.kprobe_multi.addrs = addrs;
	lopts.kprobe_multi.cnt = 1;
	lopts.kprobe_multi.flags = BPF_F_KPROBE_MULTI_INLINE;

	if (!inline_link_fails(prog_fd, BPF_TRACE_KPROBE_MULTI, &lopts, -EINVAL,
			       "Inlined functions need to be specified with kprobe_multi.syms."))
		goto cleanup;

	/* fail_2 - inlined with return probe */
	LIBBPF_OPTS_RESET(opts,
		.syms = syms,
		.cnt = 1,
		.inlined = true,
		.retprobe = true,
	);

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_inline,
						     NULL, &opts);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "fail_2"))
		goto cleanup;
	ASSERT_EQ(saved_error, -EINVAL, "fail_2_error");

	LIBBPF_OPTS_RESET(lopts,
		.kprobe_multi.syms = syms,
		.kprobe_multi.cnt = 1,
		.kprobe_multi.flags = BPF_F_KPROBE_MULTI_INLINE | BPF_F_KPROBE_MULTI_RETURN,
	);

	if (!inline_link_fails(prog_fd, BPF_TRACE_KPROBE_MULTI, &lopts, -EINVAL,
			       "Inlined functions can't be attached with return probe."))
		goto cleanup;

	/* fail_3 - inlined with session program */
	lopts.kprobe_multi.flags = BPF_F_KPROBE_MULTI_INLINE;

	if (!inline_link_fails(bpf_program__fd(skel->progs.test_session_inline),
			       BPF_TRACE_KPROBE_SESSION, &lopts, -EINVAL,
			       "Inlined functions can't be attached with session or override "
			       "program."))
		goto cleanup;

	/* fail_4 - inlined with wildcard pattern */
	LIBBPF_OPTS_RESET(opts,
		.inlined = true,
	);

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_inline,
						     "bpf_kprobe_multi_inline_*", &opts);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "fail_4"))
		goto cleanup;
	ASSERT_EQ(saved_error, -EINVAL, "fail_4_error");

	/* fail_5 - function with no entry and no inlined instance */
	LIBBPF_OPTS_RESET(opts,
		.syms = nosyms,
		.cnt = 1,
		.inlined = true,
	);

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_inline,
						     NULL, &opts);
	saved_error = -errno;
	if (!ASSERT_ERR_PTR(link, "fail_5"))
		goto cleanup;
	ASSERT_EQ(saved_error, -ENOENT, "fail_5_error");

	LIBBPF_OPTS_RESET(lopts,
		.kprobe_multi.syms = nosyms,
		.kprobe_multi.cnt = 1,
		.kprobe_multi.flags = BPF_F_KPROBE_MULTI_INLINE,
	);

	if (!inline_link_fails(prog_fd, BPF_TRACE_KPROBE_MULTI, &lopts, -ESRCH,
			       "Function bpf_kprobe_multi_inline_nonexistent has no entry and "
			       "no inlined instance."))
		goto cleanup;

	/* fail_6 - function with no entry and no inlined instance that can be attached */
	lopts.kprobe_multi.syms = nokprobe;

	inline_link_fails(prog_fd, BPF_TRACE_KPROBE_MULTI, &lopts, -EINVAL,
			  "Function " INLINE_NOKPROBE " has no entry and none of its "
			  "inlined instances can be attached, bpf_kprobe_multi_inline_test4+");

cleanup:
	bpf_link__destroy(link);
	kprobe_multi_inline__destroy(skel);
}

void serial_test_kprobe_multi_bench_attach(void)
{
	if (test__start_subtest("kernel"))
		test_kprobe_multi_bench_attach(true);
	if (test__start_subtest("modules"))
		test_kprobe_multi_bench_attach(false);
	if (test__start_subtest("kernel"))
		test_kprobe_multi_bench_attach_addr(true);
	if (test__start_subtest("modules"))
		test_kprobe_multi_bench_attach_addr(false);
}

void test_kprobe_multi_test(void)
{
	if (!ASSERT_OK(load_kallsyms(), "load_kallsyms"))
		return;

	if (test__start_subtest("skel_api"))
		test_skel_api();
	if (test__start_subtest("link_api_addrs"))
		test_link_api_syms();
	if (test__start_subtest("link_api_syms"))
		test_link_api_addrs();
	if (test__start_subtest("attach_api_pattern"))
		test_attach_api_pattern();
	if (test__start_subtest("attach_api_addrs"))
		test_attach_api_addrs();
	if (test__start_subtest("attach_api_syms"))
		test_attach_api_syms();
	if (test__start_subtest("attach_api_fails"))
		test_attach_api_fails();
	if (test__start_subtest("attach_override"))
		test_attach_override();
	if (test__start_subtest("override"))
		test_override();
	if (test__start_subtest("session"))
		test_session_skel_api();
	if (test__start_subtest("session_cookie"))
		test_session_cookie_skel_api();
	if (test__start_subtest("unique_match"))
		test_unique_match();
	if (test__start_subtest("attach_write_ctx"))
		test_attach_write_ctx();
	if (test__start_subtest("dup_sym"))
		test_attach_probe_dup_sym();
	if (test__start_subtest("inline_attach"))
		test_inline(false);
	if (test__start_subtest("inline_same_addr"))
		test_inline(true);
	if (test__start_subtest("inline_mixed"))
		test_inline_mixed();
	if (test__start_subtest("inline_skip"))
		test_inline_skip();
	if (test__start_subtest("inline_fails"))
		test_inline_fails();
	if (test__start_subtest("inline_module"))
		test_inline_module();
	RUN_TESTS(kprobe_multi_verifier);
}
