/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SITE_INDEX_H
#define _LINUX_SITE_INDEX_H

#include <linux/types.h>

/*
 * Index of a code patch site table (jump entries, static call sites)
 * sorted by code address, used for text reservation lookups. The site
 * tables themselves are sorted by key, so they cannot be searched by
 * address directly.
 */

/* Return the code address of a table entry. */
typedef unsigned long (*site_index_addr_t)(const void *entry);

struct site_index {
	struct rcu_head rcu;
	unsigned int nr;
	void *entries[];
};

struct site_index *site_index_alloc(void *base, size_t size, unsigned int nr,
				    site_index_addr_t addr);

/**
 * site_index_find - find the first entry that may overlap @start
 * @index: index built by site_index_alloc()
 * @start: start of the text range
 * @addr: the same address callback used to build @index
 *
 * Callers scan forward from the returned position until an entry's
 * address is past the end of their range. Always inlined, so a constant
 * @addr does not turn into an indirect call.
 *
 * Return: position of the last entry at or before @start, or 0.
 */
static __always_inline unsigned int
site_index_find(const struct site_index *index, unsigned long start,
		site_index_addr_t addr)
{
	unsigned int low = 0, high = index->nr;

	/* Find the first entry after @start. */
	while (low < high) {
		unsigned int mid = low + (high - low) / 2;

		if (addr(index->entries[mid]) <= start)
			low = mid + 1;
		else
			high = mid;
	}

	/* The preceding entry may start before @start and overlap it. */
	return low ? low - 1 : 0;
}

#endif /* _LINUX_SITE_INDEX_H */
