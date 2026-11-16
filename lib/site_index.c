// SPDX-License-Identifier: GPL-2.0
/*
 * Address-sorted index of code patch site tables.
 */
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/site_index.h>

static int site_index_cmp(const void *a, const void *b, const void *priv)
{
	site_index_addr_t addr = *(const site_index_addr_t *)priv;
	unsigned long ca = addr(*(void * const *)a);
	unsigned long cb = addr(*(void * const *)b);

	return cmp_int(ca, cb);
}

/**
 * site_index_alloc - build an address-sorted index of a site table
 * @base: first entry of the table
 * @size: size of one table entry
 * @nr: number of table entries
 * @addr: returns the code address of an entry
 *
 * The index points into the table, so it must be freed (kvfree() or
 * kvfree_rcu()) before the table goes away.
 *
 * Return: the index, or NULL if @nr is zero or allocation fails. Callers
 * fall back to scanning the table linearly in that case.
 */
struct site_index *site_index_alloc(void *base, size_t size, unsigned int nr,
				    site_index_addr_t addr)
{
	struct site_index *index;
	unsigned int i;

	if (!nr)
		return NULL;

	index = kvmalloc_flex(*index, entries, nr, GFP_KERNEL);
	if (!index)
		return NULL;

	index->nr = nr;
	for (i = 0; i < nr; i++)
		index->entries[i] = base + i * size;

	sort_r(index->entries, nr, sizeof(index->entries[0]),
	       site_index_cmp, NULL, &addr);
	return index;
}
