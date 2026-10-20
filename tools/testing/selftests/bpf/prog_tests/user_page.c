// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <unistd.h>

#include "user_page.skel.h"

enum {
	USER_PAGE_ALLOC = 1,
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

out:
	user_page__destroy(skel);
}
