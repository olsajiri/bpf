// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "stacktrace_map.skel.h"

static void test_stacktrace_map_tp(void)
{
	struct stacktrace_map *skel;
	int control_map_fd, stackid_hmap_fd, stackmap_fd, stack_amap_fd;
	int err, stack_trace_len;
	__u32 key, val, stack_id, duration = 0;
	__u64 stack[PERF_MAX_STACK_DEPTH];

	skel = stacktrace_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	control_map_fd = bpf_map__fd(skel->maps.control_map);
	stackid_hmap_fd = bpf_map__fd(skel->maps.stackid_hmap);
	stackmap_fd = bpf_map__fd(skel->maps.stackmap);
	stack_amap_fd = bpf_map__fd(skel->maps.stack_amap);

	err = stacktrace_map__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;
	/* give some time for bpf program run */
	sleep(1);

	/* disable stack trace collection */
	key = 0;
	val = 1;
	bpf_map_update_elem(control_map_fd, &key, &val, 0);

	/* for every element in stackid_hmap, we can find a corresponding one
	 * in stackmap, and vice versa.
	 */
	err = compare_map_keys(stackid_hmap_fd, stackmap_fd);
	if (CHECK(err, "compare_map_keys stackid_hmap vs. stackmap",
		  "err %d errno %d\n", err, errno))
		goto out;

	err = compare_map_keys(stackmap_fd, stackid_hmap_fd);
	if (CHECK(err, "compare_map_keys stackmap vs. stackid_hmap",
		  "err %d errno %d\n", err, errno))
		goto out;

	stack_trace_len = PERF_MAX_STACK_DEPTH * sizeof(__u64);
	err = compare_stack_ips(stackmap_fd, stack_amap_fd, stack_trace_len);
	if (CHECK(err, "compare_stack_ips stackmap vs. stack_amap",
		  "err %d errno %d\n", err, errno))
		goto out;

	stack_id = skel->bss->stack_id;
	err = bpf_map_lookup_and_delete_elem(stackmap_fd, &stack_id,  stack);
	if (!ASSERT_OK(err, "lookup and delete target stack_id"))
		goto out;

	err = bpf_map_lookup_elem(stackmap_fd, &stack_id, stack);
	if (!ASSERT_EQ(err, -ENOENT, "lookup deleted stack_id"))
		goto out;
out:
	stacktrace_map__destroy(skel);
}

static void test_stacktrace_map_double_entry(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct stacktrace_map *skel;
	int prog_fd, err;

	skel = stacktrace_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	skel->links.test = bpf_program__attach_trace(skel->progs.test);
	if (!ASSERT_OK_PTR(skel->links.test, "bpf_program__attach_trace"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.trigger);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test_result, true, "result");

cleanup:
	stacktrace_map__destroy(skel);
}

void test_stacktrace_map(void)
{
	if (test__start_subtest("tp"))
		test_stacktrace_map_tp();
	if (test__start_subtest("double_entry"))
		test_stacktrace_map_double_entry();
}
