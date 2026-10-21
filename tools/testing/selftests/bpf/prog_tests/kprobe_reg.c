// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <sys/resource.h>
#include "kprobe_reg.skel.h"
#include "test_kmods/bpf_testmod_kprobe_targets.h"

#define KPROBE_REG_MAX_ITERATIONS 1000
#define KPROBE_REG_FD_HEADROOM 16

static bool parse_env_count(const char *name, int default_value, int max_value,
			    int *value)
{
	const char *str = getenv(name);
	char *end;
	long parsed;

	if (!str) {
		*value = default_value;
		return true;
	}

	errno = 0;
	parsed = strtol(str, &end, 10);
	if (errno || end == str || *end || parsed < 1 || parsed > max_value)
		return false;

	*value = parsed;
	return true;
}

void test_kprobe_reg(void)
{
	struct kprobe_reg *skel = NULL;
	struct bpf_link **links = NULL;
	char (*func_names)[64] = NULL;
	struct rlimit old_limit, new_limit;
	const char *slow_tests = getenv("SLOW_TESTS");
	__u64 total_attach_ns = 0, total_detach_ns = 0;
	int count, iterations, i, iter;
	bool changed_limit = false;

	if (!slow_tests || strcmp(slow_tests, "1")) {
		test__skip();
		return;
	}
	if (!env.has_testmod) {
		test__skip();
		return;
	}
	if (!ASSERT_TRUE(parse_env_count("BPF_KPROBE_REG_COUNT",
					 BPF_TESTMOD_KPROBE_TARGET_COUNT,
					 BPF_TESTMOD_KPROBE_TARGET_COUNT, &count),
			"kprobe_count"))
		return;
	if (!ASSERT_TRUE(parse_env_count("BPF_KPROBE_REG_ITERATIONS", 1,
					 KPROBE_REG_MAX_ITERATIONS, &iterations),
			"kprobe_iterations"))
		return;

	if (!ASSERT_OK(getrlimit(RLIMIT_NOFILE, &old_limit), "getrlimit"))
		return;
	new_limit = old_limit;
	if (new_limit.rlim_cur < count + KPROBE_REG_FD_HEADROOM) {
		if (new_limit.rlim_max < count + KPROBE_REG_FD_HEADROOM) {
			test__skip();
			return;
		}
		new_limit.rlim_cur = count + KPROBE_REG_FD_HEADROOM;
		if (!ASSERT_OK(setrlimit(RLIMIT_NOFILE, &new_limit), "setrlimit"))
			return;
		changed_limit = true;
	}

	links = calloc(count, sizeof(*links));
	func_names = calloc(count, sizeof(*func_names));
	if (!ASSERT_OK_PTR(links, "links") || !ASSERT_OK_PTR(func_names, "func_names"))
		goto cleanup;
	for (i = 0; i < count; i++)
		snprintf(func_names[i], sizeof(*func_names[i]),
			 "bpf_testmod_kprobe_target_%d", i);

	skel = kprobe_reg__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto cleanup;

	for (iter = 0; iter < iterations; iter++) {
		__u64 start;

		start = get_time_ns();
		for (i = 0; i < count; i++) {
			links[i] = bpf_program__attach_kprobe(
				skel->progs.kprobe_reg, false, func_names[i]);
			if (!ASSERT_OK_PTR(links[i], "attach_kprobe"))
				goto cleanup;
		}
		total_attach_ns += get_time_ns() - start;

		start = get_time_ns();
		for (i = 0; i < count; i++) {
			bpf_link__destroy(links[i]);
			links[i] = NULL;
		}
		total_detach_ns += get_time_ns() - start;
	}

	printf("kprobe_reg: %d probes x %d iterations; attach %.3lf us/probe, "
	       "detach %.3lf us/probe\n", count, iterations,
	       total_attach_ns / 1000.0 / count / iterations,
	       total_detach_ns / 1000.0 / count / iterations);

cleanup:
	if (links) {
		for (i = 0; i < count; i++) {
			if (links[i])
				bpf_link__destroy(links[i]);
		}
	}
	kprobe_reg__destroy(skel);
	free(func_names);
	free(links);
	if (changed_limit)
		ASSERT_OK(setrlimit(RLIMIT_NOFILE, &old_limit), "restore_rlimit");
}
