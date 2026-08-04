// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook
#include "vmlinux.h"
#include <asm/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf/usdt.bpf.h"

char _license[] SEC("license") = "GPL";

#define CLOCK_MONOTONIC 1
#define CPU_MASK 255
#define MAX_CPUS (CPU_MASK + 1) /* should match MAX_BUCKETS in benchs/bench_trigger.c */

/* matches struct counter in bench.h */
struct counter {
	long value;
} __attribute__((aligned(128)));

struct counter hits[MAX_CPUS];

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 4096);
} user_ringbuf SEC(".maps");

struct user_ringbuf_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct user_ringbuf_timer);
} user_ringbuf_timers SEC(".maps");

struct counter user_ringbuf_timer_fires;

const volatile __u64 user_ringbuf_timer_ns = 1000000;
const volatile __u32 user_ringbuf_target_tgid;

static __always_inline void inc_counter(void)
{
	int cpu = bpf_get_smp_processor_id();

	__sync_add_and_fetch(&hits[cpu & CPU_MASK].value, 1);
}

volatile const int stacktrace;

typedef __u64 stack_trace_t[128];

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	 __uint(max_entries, 1);
	__type(key, __u32);
	__type(value, stack_trace_t);
} stack_heap SEC(".maps");

static __always_inline void do_stacktrace(void *ctx)
{
	if (!stacktrace)
		return;

	__u64 *ptr = bpf_map_lookup_elem(&stack_heap, &(__u32){0});

	if (ptr)
		bpf_get_stack(ctx, ptr, sizeof(stack_trace_t), 0);
}

static __always_inline void handle(void *ctx)
{
	inc_counter();
	do_stacktrace(ctx);
}

static long user_ringbuf_timer_drain_cb(struct bpf_dynptr *dynptr, void *ctx)
{
	inc_counter();
	return 0;
}

static long user_ringbuf_syscall_drain_cb(struct bpf_dynptr *dynptr, void *ctx)
{
	inc_counter();
	return 1;
}

static int user_ringbuf_timer_cb(void *map, __u32 *key,
				  struct user_ringbuf_timer *value)
{
	__sync_add_and_fetch(&user_ringbuf_timer_fires.value, 1);
	bpf_user_ringbuf_drain(&user_ringbuf, user_ringbuf_timer_drain_cb, NULL, 0);
	bpf_timer_start(&value->timer, user_ringbuf_timer_ns, 0);
	return 0;
}

SEC("?ksyscall/getppid")
int trigger_user_ringbuf_syscall(void *ctx)
{
	if (bpf_get_current_pid_tgid() >> 32 != user_ringbuf_target_tgid)
		return 0;

	bpf_user_ringbuf_drain(&user_ringbuf,
			       user_ringbuf_syscall_drain_cb, NULL, 0);
	return 0;
}

SEC("?syscall")
int trigger_user_ringbuf_timer_init(void *ctx)
{
	struct user_ringbuf_timer *value;
	__u32 key = 0;
	int err;

	value = bpf_map_lookup_elem(&user_ringbuf_timers, &key);
	if (!value)
		return 1;

	err = bpf_timer_init(&value->timer, &user_ringbuf_timers,
			     CLOCK_MONOTONIC);
	if (err)
		return err;

	err = bpf_timer_set_callback(&value->timer, user_ringbuf_timer_cb);
	if (err)
		return err;

	return bpf_timer_start(&value->timer, user_ringbuf_timer_ns, 0);
}

SEC("?uprobe")
int bench_trigger_uprobe(void *ctx)
{
	inc_counter();
	return 0;
}

SEC("?uprobe.multi")
int bench_trigger_uprobe_multi(void *ctx)
{
	inc_counter();
	return 0;
}

const volatile int batch_iters = 0;

SEC("?raw_tp")
int trigger_kernel_count(void *ctx)
{
	int i;

	for (i = 0; i < batch_iters; i++) {
		inc_counter();
		bpf_get_numa_node_id();
	}

	return 0;
}

SEC("?raw_tp")
int trigger_driver(void *ctx)
{
	int i;

	for (i = 0; i < batch_iters; i++)
		(void)bpf_get_numa_node_id(); /* attach point for benchmarking */

	return 0;
}

extern int bpf_modify_return_test_tp(int nonce) __ksym __weak;

SEC("?raw_tp")
int trigger_driver_kfunc(void *ctx)
{
	int i;

	for (i = 0; i < batch_iters; i++)
		(void)bpf_modify_return_test_tp(0); /* attach point for benchmarking */

	return 0;
}

SEC("?kprobe/bpf_get_numa_node_id")
int bench_trigger_kprobe(void *ctx)
{
	handle(ctx);
	return 0;
}

SEC("?kretprobe/bpf_get_numa_node_id")
int bench_trigger_kretprobe(void *ctx)
{
	handle(ctx);
	return 0;
}

SEC("?kprobe.multi/bpf_get_numa_node_id")
int bench_trigger_kprobe_multi(void *ctx)
{
	handle(ctx);
	return 0;
}

SEC("?kprobe.multi/bpf_get_numa_node_id")
int bench_kprobe_multi_empty(void *ctx)
{
	return 0;
}

SEC("?kretprobe.multi/bpf_get_numa_node_id")
int bench_trigger_kretprobe_multi(void *ctx)
{
	handle(ctx);
	return 0;
}

SEC("?kretprobe.multi/bpf_get_numa_node_id")
int bench_kretprobe_multi_empty(void *ctx)
{
	return 0;
}

SEC("?fentry/bpf_get_numa_node_id")
int bench_trigger_fentry(void *ctx)
{
	handle(ctx);
	return 0;
}

SEC("?fexit/bpf_get_numa_node_id")
int bench_trigger_fexit(void *ctx)
{
	handle(ctx);
	return 0;
}

SEC("?fmod_ret/bpf_modify_return_test_tp")
int bench_trigger_fmodret(void *ctx)
{
	handle(ctx);
	return -22;
}

SEC("?tp/bpf_test_run/bpf_trigger_tp")
int bench_trigger_tp(void *ctx)
{
	handle(ctx);
	return 0;
}

SEC("?raw_tp/bpf_trigger_tp")
int bench_trigger_rawtp(void *ctx)
{
	handle(ctx);
	return 0;
}

SEC("?usdt")
int bench_trigger_usdt(void *ctx)
{
	inc_counter();
	return 0;
}
