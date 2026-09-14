// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Isovalent */

#include <test_progs.h>
#include "testing_helpers.h"
#include <bpf/btf.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#define BTF_SYSFS_DIR		"/sys/kernel/btf"
#define BTF_INLINE_SUFFIX	".inline"

static void test_btf_mmap_sysfs(const char *path, struct btf *base)
{
	struct stat st;
	__u64 btf_size, end;
	void *raw_data = NULL;
	int fd = -1;
	long page_size;
	struct btf *btf = NULL;

	page_size = sysconf(_SC_PAGESIZE);
	if (!ASSERT_GE(page_size, 0, "get_page_size"))
		goto cleanup;

	if (!ASSERT_OK(stat(path, &st), "stat_btf"))
		goto cleanup;

	btf_size = st.st_size;
	end = (btf_size + page_size - 1) / page_size * page_size;

	fd = open(path, O_RDONLY);
	if (!ASSERT_GE(fd, 0, "open_btf"))
		goto cleanup;

	raw_data = mmap(NULL, btf_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (!ASSERT_EQ(raw_data, MAP_FAILED, "mmap_btf_writable"))
		goto cleanup;

	raw_data = mmap(NULL, btf_size, PROT_READ, MAP_SHARED, fd, 0);
	if (!ASSERT_EQ(raw_data, MAP_FAILED, "mmap_btf_shared"))
		goto cleanup;

	raw_data = mmap(NULL, end + 1, PROT_READ, MAP_PRIVATE, fd, 0);
	if (!ASSERT_EQ(raw_data, MAP_FAILED, "mmap_btf_invalid_size"))
		goto cleanup;

	raw_data = mmap(NULL, end, PROT_READ, MAP_PRIVATE, fd, 0);
	if (!ASSERT_OK_PTR(raw_data, "mmap_btf"))
		goto cleanup;

	if (!ASSERT_EQ(mprotect(raw_data, btf_size, PROT_READ | PROT_WRITE), -1,
	    "mprotect_writable"))
		goto cleanup;

	if (!ASSERT_EQ(mprotect(raw_data, btf_size, PROT_READ | PROT_EXEC), -1,
	    "mprotect_executable"))
		goto cleanup;

	/* Check padding is zeroed */
	for (int i = btf_size; i < end; i++) {
		if (((__u8 *)raw_data)[i] != 0) {
			PRINT_FAIL("tail of BTF is not zero at page offset %d\n", i);
			goto cleanup;
		}
	}

	btf = btf__new_split(raw_data, btf_size, base);
	if (!ASSERT_OK_PTR(btf, "parse_btf"))
		goto cleanup;

cleanup:
	btf__free(btf);
	if (raw_data && raw_data != MAP_FAILED)
		munmap(raw_data, btf_size);
	if (fd >= 0)
		close(fd);
}

static void test_btf_inline_sysfs_all(void)
{
	struct btf *vmlinux_btf;
	struct dirent *dentry;
	DIR *dir;
	int err = 0;

	dir = opendir(BTF_SYSFS_DIR);
	if (!ASSERT_OK_PTR(dir, "open_btf_sysfs"))
		return;

	vmlinux_btf = btf__parse(BTF_SYSFS_DIR "/vmlinux", NULL);
	if (!ASSERT_OK_PTR(vmlinux_btf, "parse_vmlinux_btf")) {
		closedir(dir);
		return;
	}

	while ((dentry = readdir(dir)) != NULL) {
		struct btf *base_btf = NULL, *module_btf = NULL, *inline_btf = NULL;
		char btf_path[PATH_MAX], inline_path[PATH_MAX];
		struct stat st;

		/* Skip ".", ".." and "foo.inline" */
		if (strstr(dentry->d_name, "."))
			continue;

		if (strcmp(dentry->d_name, "vmlinux") == 0)
			base_btf = vmlinux_btf;

		if (snprintf(btf_path, sizeof(btf_path), "%s/%s",
			     BTF_SYSFS_DIR, dentry->d_name) >= sizeof(btf_path) ||
		    snprintf(inline_path, sizeof(inline_path), "%s/%s%s",
			     BTF_SYSFS_DIR, dentry->d_name, BTF_INLINE_SUFFIX) >=
			     sizeof(inline_path)) {
			ASSERT_FAIL("BTF sysfs path is too long\n");
			break;
		}

		if (!base_btf) {
			module_btf = btf__parse_split(btf_path, vmlinux_btf);
			err = libbpf_get_error(module_btf);
			if (err) {
				/* A module can be unloaded while its sysfs entry is iterated. */
				if (err == -ENOENT)
					continue;
				ASSERT_OK(err, "parse_module_btf");
				continue;
			}
			base_btf = module_btf;
		}
		if (stat(inline_path, &st)) {
			err = errno;
			if (err == ENOENT)
				continue;
			ASSERT_OK(err, "stat_inline_btf");
		}
		inline_btf = btf__parse_split(inline_path, base_btf);
		err = libbpf_get_error(inline_btf);
		if (!err)
			btf__free(inline_btf);
		ASSERT_OK(err, "parse_inline_btf");
		btf__free(module_btf);
	}
	closedir(dir);

	btf__free(vmlinux_btf);
}

static bool read_btf_sysfs(const char *path, void **data, size_t *size)
{
	struct stat st;
	size_t off = 0;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY);
	if (!ASSERT_GE(fd, 0, "open_btf_sysfs"))
		return false;
	if (!ASSERT_OK(fstat(fd, &st), "stat_btf_sysfs"))
		goto err_close;
	if (!ASSERT_GT(st.st_size, 0, "btf_sysfs_size"))
		goto err_close;

	*size = st.st_size;
	*data = malloc(*size);
	if (!ASSERT_OK_PTR(*data, "alloc_btf_sysfs"))
		goto err_close;

	while (off < *size) {
		n = read(fd, *data + off, *size - off);
		if (!ASSERT_GT(n, 0, "read_btf_sysfs")) {
			free(*data);
			*data = NULL;
			goto err_close;
		}
		off += n;
	}
	close(fd);
	return true;

err_close:
	close(fd);
	return false;
}

static void test_btf_inline_sysfs_reload(void)
{
	const char *module_path = "/sys/module/btf_vmlinux_inline";
	const char *inline_path = BTF_SYSFS_DIR "/vmlinux.inline";
	struct stat st;
	void *first = NULL, *second = NULL;
	size_t first_size, second_size;

	/* A built-in inline BTF representation has no carrier module to reload. */
	if (stat(inline_path, &st))
		return;

	if (!read_btf_sysfs(inline_path, &first, &first_size))
		return;
	if (stat(module_path, &st))
		goto out;
	if (!ASSERT_OK(unload_module("btf_vmlinux_inline", false),
		       "unload_btf_vmlinux_inline"))
		goto out;
	if (!read_btf_sysfs(inline_path, &second, &second_size))
		goto out;

	ASSERT_EQ(first_size, second_size, "reloaded_btf_size");
	ASSERT_OK(memcmp(first, second, first_size), "reloaded_btf_data");
out:
	free(first);
	free(second);
}

void test_btf_sysfs(void)
{
	test_btf_mmap_sysfs("/sys/kernel/btf/vmlinux", NULL);
	test_btf_inline_sysfs_all();
	test_btf_inline_sysfs_reload();
}
