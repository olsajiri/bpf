// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

enum {
	USER_MEM_MAP = 1,
	USER_MEM_COPY = 2,
	USER_MEM_BAD_COPY = 3,
	USER_MEM_BAD_COPY_FLAGS = 4,
	USER_MEM_UNMAP = 5,
};

int monitored_pid;
int action;
unsigned long map_len;
unsigned long map_prot;
u64 copy_flags;
long user_addr;
int op_ret;

static const char data[] = "fault-enabled BPF write";

SEC("uprobe.s//proc/self/exe:user_page_trigger")
int user_page_test(struct pt_regs *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	switch (action) {
	case USER_MEM_MAP:
		user_addr = bpf_user_mmap(map_len, map_prot);
		break;
	case USER_MEM_COPY:
		op_ret = bpf_copy_to_user_task((void *)user_addr, data, sizeof(data),
					       bpf_get_current_task_btf(), 0);
		break;
	case USER_MEM_BAD_COPY:
		op_ret = bpf_copy_to_user_task((void *)1, data, sizeof(data),
					       bpf_get_current_task_btf(), 0);
		break;
	case USER_MEM_BAD_COPY_FLAGS:
		op_ret = bpf_copy_to_user_task((void *)user_addr, data, sizeof(data),
					       bpf_get_current_task_btf(), copy_flags);
		break;
	case USER_MEM_UNMAP:
		op_ret = bpf_user_munmap(user_addr, map_len);
		break;
	}

	return 0;
}
