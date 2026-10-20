// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <unistd.h>

#include "user_page.skel.h"

enum {
	USER_PAGE_ALLOC = 1,
	USER_PAGE_EXEC = 2,
	USER_PAGE_BAD_EXEC = 3,
	USER_PAGE_WRITE = 4,
	USER_PAGE_BAD_WRITE = 5,
};

static noinline int user_page_trigger(void)
{
	asm volatile ("");
	return 0;
}

static bool check_user_page_vma(void *addr, unsigned long expected_start,
				long expected_size, const char *perms)
{
	unsigned long start, end;
	char vma_perms[5];
	char line[512];
	FILE *maps;
	bool found = false;

	maps = fopen("/proc/self/maps", "r");
	if (!ASSERT_OK_PTR(maps, "open_maps"))
		return false;

	while (fgets(line, sizeof(line), maps)) {
		if (sscanf(line, "%lx-%lx %4s", &start, &end, vma_perms) != 3 ||
		    (unsigned long)addr < start || (unsigned long)addr >= end)
			continue;
		found = ASSERT_EQ(start, expected_start, "vma_start") &&
			ASSERT_EQ(end - start, expected_size, "vma_size") &&
			(!perms || ASSERT_STREQ(vma_perms, perms, "vma_perms"));
		break;
	}
	fclose(maps);
	return ASSERT_TRUE(found, "user_page_vma");
}

static bool alloc_user_pages(struct user_page *skel, unsigned long nr_pages,
			     long *addr)
{
	skel->bss->nr_pages = nr_pages;
	skel->bss->action = USER_PAGE_ALLOC;
	if (!ASSERT_EQ(user_page_trigger(), 0, "allocate") ||
	    !ASSERT_GE(skel->bss->user_addr, 0, "user_addr"))
		return false;

	*addr = skel->bss->user_addr;
	return true;
}

static void test_invalid_allocation_size(struct user_page *skel)
{
	skel->bss->action = USER_PAGE_ALLOC;
	skel->bss->nr_pages = 0;
	if (!ASSERT_EQ(user_page_trigger(), 0, "allocate_zero_pages") ||
	    !ASSERT_EQ(skel->bss->user_addr, -EINVAL, "zero_pages_ret"))
		return;

	skel->bss->nr_pages = ~0UL;
	if (!ASSERT_EQ(user_page_trigger(), 0, "allocate_overflow_pages"))
		return;
	ASSERT_EQ(skel->bss->user_addr, -EINVAL, "overflow_pages_ret");
}

static void test_isolated_allocations(struct user_page *skel)
{
	void *pages[2] = { MAP_FAILED, MAP_FAILED };
	long page_size = sysconf(_SC_PAGESIZE);
	const unsigned long nr_pages = 3;
	int i;
	long addr;

	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		if (!alloc_user_pages(skel, nr_pages, &addr))
			goto out;
		pages[i] = (void *)addr;
	}

	/* Back-to-back allocations must remain individual VMAs. */
	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		if (!check_user_page_vma(pages[i], (unsigned long)pages[i],
					 page_size * nr_pages, NULL))
			goto out;
	}
out:
	for (i = 0; i < ARRAY_SIZE(pages); i++)
		if (pages[i] != MAP_FAILED)
			munmap(pages[i], page_size * nr_pages);
}

static void test_misaligned_exec(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;

	if (!alloc_user_pages(skel, 1, &addr))
		goto out;

	skel->bss->exec_addr = addr + 1;
	skel->bss->action = USER_PAGE_BAD_EXEC;
	if (!ASSERT_EQ(user_page_trigger(), 0, "make_misaligned_exec"))
		goto out;
	ASSERT_EQ(skel->bss->exec_ret, -EINVAL, "misaligned_exec_ret");
out:
	if (addr >= 0)
		munmap((void *)addr, page_size);
}

static void test_partial_exec(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;

	if (!alloc_user_pages(skel, 3, &addr))
		goto out;

	skel->bss->exec_addr = addr + page_size;
	skel->bss->action = USER_PAGE_BAD_EXEC;
	if (!ASSERT_EQ(user_page_trigger(), 0, "make_middle_page_exec") ||
	    !ASSERT_OK(skel->bss->exec_ret, "middle_page_exec_ret") ||
	    !check_user_page_vma((void *)(addr + page_size), addr + page_size,
				 page_size, "r-xp") ||
	    !check_user_page_vma((void *)addr, addr, page_size, "rw-p") ||
	    !check_user_page_vma((void *)(addr + 2 * page_size),
				 addr + 2 * page_size, page_size, "rw-p"))
		goto out;

	skel->bss->exec_addr = addr + 2 * page_size;
	if (!ASSERT_EQ(user_page_trigger(), 0, "make_last_page_exec") ||
	    !ASSERT_OK(skel->bss->exec_ret, "last_page_exec_ret"))
		goto out;
	check_user_page_vma((void *)(addr + 2 * page_size), addr + 2 * page_size,
			    page_size, "r-xp");
out:
	if (addr >= 0)
		munmap((void *)addr, page_size * 3);
}

static void test_reject_replacement(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;
	void *ret;

	if (!alloc_user_pages(skel, 1, &addr))
		goto out;

	ret = mmap((void *)addr, page_size, PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (!ASSERT_EQ(ret, (void *)addr, "replace_mmap"))
		goto out;

	skel->bss->exec_addr = addr;
	skel->bss->action = USER_PAGE_BAD_EXEC;
	if (!ASSERT_EQ(user_page_trigger(), 0, "make_exec"))
		goto out;
	ASSERT_EQ(skel->bss->exec_ret, -EINVAL, "replacement_not_bpf");
out:
	if (addr >= 0)
		munmap((void *)addr, page_size);
}

static void test_read_implies_exec(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;
	int personality_flags;
	bool restore_personality = false;

	personality_flags = personality(0xffffffff);
	if (!ASSERT_GE(personality_flags, 0, "get_personality"))
		goto out;
	if (personality(personality_flags | READ_IMPLIES_EXEC) == -1) {
		test__skip();
		goto out;
	}
	restore_personality = true;

	if (!alloc_user_pages(skel, 1, &addr) ||
	    !check_user_page_vma((void *)addr, addr, page_size, "rwxp"))
		goto out;

	skel->bss->exec_addr = addr;
	skel->bss->action = USER_PAGE_BAD_EXEC;
	if (!ASSERT_EQ(user_page_trigger(), 0, "make_exec") ||
	    !ASSERT_OK(skel->bss->exec_ret, "exec_ret"))
		goto out;
	check_user_page_vma((void *)addr, addr, page_size, "r-xp");
out:
	if (restore_personality)
		ASSERT_GE(personality(personality_flags), 0, "restore_personality");
	if (addr >= 0)
		munmap((void *)addr, page_size);
}

static void test_lazy_allocation(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;
	unsigned char vec;
	int err;

	if (!alloc_user_pages(skel, 1, &addr))
		goto out;

	err = mincore((void *)addr, page_size, &vec);
	if (!ASSERT_OK(err, "mincore_before_write"))
		goto out;
	ASSERT_EQ(vec & 1, 0, "page_not_resident");
out:
	if (addr >= 0)
		munmap((void *)addr, page_size);
}

static void test_faultable_write(struct user_page *skel)
{
	static const char expected[] = "fault-enabled BPF write";
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;

	if (!alloc_user_pages(skel, 1, &addr))
		goto out;

	skel->bss->user_addr = addr;
	skel->bss->action = USER_PAGE_WRITE;
	if (!ASSERT_EQ(user_page_trigger(), 0, "uprobe_write") ||
	    !ASSERT_EQ(skel->bss->write_ret, 0, "write_ret"))
		goto out;
	ASSERT_EQ(memcmp((void *)addr, expected, sizeof(expected)), 0,
		  "written_data");
out:
	if (addr >= 0)
		munmap((void *)addr, page_size);
}

static void test_bad_write(struct user_page *skel)
{
	skel->bss->action = USER_PAGE_BAD_WRITE;
	if (!ASSERT_EQ(user_page_trigger(), 0, "uprobe_bad_write"))
		return;
	ASSERT_EQ(skel->bss->write_ret, -EFAULT, "bad_write_ret");
}

static void test_unrelated_mapping_exec_rejected(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	void *unrelated;

	unrelated = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_NEQ(unrelated, MAP_FAILED, "unrelated_mmap"))
		return;

	skel->bss->exec_addr = (long)unrelated;
	skel->bss->action = USER_PAGE_BAD_EXEC;
	if (!ASSERT_EQ(user_page_trigger(), 0, "uprobe_bad_exec"))
		goto out;
	ASSERT_EQ(skel->bss->exec_ret, -EINVAL, "bad_exec_ret");
out:
	munmap(unrelated, page_size);
}

static void test_execute_user_page(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;

#ifndef __x86_64__
        test__skip();
        return;
#endif

	if (!alloc_user_pages(skel, 1, &addr))
		goto out;

	skel->bss->exec_addr = addr;
	skel->bss->action = USER_PAGE_EXEC;
	if (!ASSERT_EQ(user_page_trigger(), 0, "uprobe_exec") ||
	    !ASSERT_EQ(skel->bss->write_ret, 0, "exec_write_ret") ||
	    !ASSERT_EQ(skel->bss->exec_ret, 0, "exec_ret") ||
	    !ASSERT_EQ(((int (*)(void))addr)(), 42, "execute_user_page"))
		goto out;
out:
	if (addr >= 0)
		munmap((void *)addr, page_size);
}

static void test_repeat_exec_rejected(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;

	if (!alloc_user_pages(skel, 1, &addr))
		goto out;

	skel->bss->exec_addr = addr;
	skel->bss->action = USER_PAGE_BAD_EXEC;
	if (!ASSERT_EQ(user_page_trigger(), 0, "first_exec") ||
	    !ASSERT_OK(skel->bss->exec_ret, "first_exec_ret") ||
	    !ASSERT_EQ(user_page_trigger(), 0, "repeat_exec"))
		goto out;
	ASSERT_EQ(skel->bss->exec_ret, -EINVAL, "repeat_exec_ret");
out:
	if (addr >= 0)
		munmap((void *)addr, page_size);
}

static void test_exec_write_protection(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;

	if (!alloc_user_pages(skel, 1, &addr))
		goto out;

	skel->bss->exec_addr = addr;
	skel->bss->action = USER_PAGE_BAD_EXEC;
	if (!ASSERT_EQ(user_page_trigger(), 0, "make_exec") ||
	    !ASSERT_OK(skel->bss->exec_ret, "exec_ret"))
		goto out;

	errno = 0;
	if (!ASSERT_EQ(mprotect((void *)addr, page_size,
				PROT_READ | PROT_WRITE), -1, "restore_write"))
		goto out;
	ASSERT_EQ(errno, EACCES, "restore_write_errno");
out:
	if (addr >= 0)
		munmap((void *)addr, page_size);
}

static void test_reallocate_after_unmap(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;

	if (!alloc_user_pages(skel, 1, &addr))
		goto out;

	if (!ASSERT_OK(munmap((void *)addr, page_size), "munmap"))
		goto out;
	addr = -1;
	if (!alloc_user_pages(skel, 1, &addr))
		goto out;
out:
	if (addr >= 0)
		munmap((void *)addr, page_size);
}

static void test_fails(struct user_page *skel)
{
	test_invalid_allocation_size(skel);
	test_misaligned_exec(skel);
	test_reject_replacement(skel);
	test_bad_write(skel);
	test_unrelated_mapping_exec_rejected(skel);
	test_repeat_exec_rejected(skel);
	test_exec_write_protection(skel);
}

void test_user_page(void)
{
	struct user_page *skel;

	skel = user_page__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(user_page__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("isolated_allocations"))
		test_isolated_allocations(skel);
	if (test__start_subtest("lazy_allocation"))
		test_lazy_allocation(skel);
	if (test__start_subtest("reallocate_after_unmap"))
		test_reallocate_after_unmap(skel);
	if (test__start_subtest("partial_exec"))
		test_partial_exec(skel);
	if (test__start_subtest("read_implies_exec"))
		test_read_implies_exec(skel);
	if (test__start_subtest("execute_user_page"))
		test_execute_user_page(skel);
	if (test__start_subtest("faultable_write"))
		test_faultable_write(skel);
	if (test__start_subtest("fails"))
		test_fails(skel);

out:
	user_page__destroy(skel);
}
