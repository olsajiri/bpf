// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "kprobe_multi_uprobe_tailcall.skel.h"

static noinline void trigger_uprobe(void)
{
	asm volatile ("" ::: "memory");
}

void test_kprobe_multi_uprobe_tailcall(void)
{
	LIBBPF_OPTS(bpf_uprobe_opts, opts,
		.attach_mode = PROBE_ATTACH_MODE_PERF,
		.func_name = "trigger_uprobe",
	);
	struct kprobe_multi_uprobe_tailcall *skel = NULL;
	struct bpf_link *link = NULL;
	__u32 key = 0;
	int prog_fd, err;

	skel = kprobe_multi_uprobe_tailcall__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.target);
	if (!ASSERT_GE(prog_fd, 0, "target_prog_fd"))
		goto cleanup;
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.progs), &key,
				  &prog_fd, BPF_ANY);
	if (!ASSERT_OK(err, "prog_array_update"))
		goto cleanup;

	link = bpf_program__attach_uprobe_opts(skel->progs.entry, getpid(),
						      "/proc/self/exe",
						      0, &opts);
	if (!ASSERT_OK_PTR(link, "attach_uprobe_perf"))
		goto cleanup;

	trigger_uprobe();
	ASSERT_EQ(skel->bss->target_runs, 1, "private_stack_target_ran");

cleanup:
	bpf_link__destroy(link);
	kprobe_multi_uprobe_tailcall__destroy(skel);
}
