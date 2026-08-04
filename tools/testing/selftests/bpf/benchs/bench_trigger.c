// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
#define _GNU_SOURCE
#include <argp.h>
#include <unistd.h>
#include <stdint.h>
#include "bpf_util.h"
#include "bench.h"
#include "trigger_bench.skel.h"
#include "trace_helpers.h"

#define MAX_TRIG_BATCH_ITERS 1000

static struct {
	__u32 batch_iters;
	__u32 user_rb_size;
	__u64 user_rb_timer_ns;
} args = {
	.batch_iters = 100,
	.user_rb_size = 4096,
	.user_rb_timer_ns = 1000000,
};

enum {
	ARG_TRIG_BATCH_ITERS = 7000,
	ARG_TRIG_USER_RB_TIMER_NS,
	ARG_TRIG_USER_RB_SIZE,
};

static const struct argp_option opts[] = {
	{ "trig-batch-iters", ARG_TRIG_BATCH_ITERS, "BATCH_ITER_CNT", 0,
		"Number of in-kernel iterations per one driver test run"},
	{ "user-rb-timer-ns", ARG_TRIG_USER_RB_TIMER_NS, "NSEC", 0,
		"User ring buffer drain timer interval in nanoseconds"},
	{ "user-rb-size", ARG_TRIG_USER_RB_SIZE, "BYTES", 0,
		"User ring buffer size in bytes"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	unsigned long long value;
	char *end;
	long ret;

	switch (key) {
	case ARG_TRIG_BATCH_ITERS:
		ret = strtol(arg, NULL, 10);
		if (ret < 1 || ret > MAX_TRIG_BATCH_ITERS) {
			fprintf(stderr, "invalid --trig-batch-iters value (should be between %d and %d)\n",
				1, MAX_TRIG_BATCH_ITERS);
			argp_usage(state);
		}
		args.batch_iters = ret;
		break;
	case ARG_TRIG_USER_RB_TIMER_NS:
		errno = 0;
		value = strtoull(arg, &end, 10);
		if (errno || end == arg || *end || arg[0] == '-' || !value) {
			fprintf(stderr, "invalid --user-rb-timer-ns value (should be positive)\n");
			argp_usage(state);
		}
		args.user_rb_timer_ns = value;
		break;
	case ARG_TRIG_USER_RB_SIZE:
		errno = 0;
		value = strtoull(arg, &end, 10);
		if (errno || end == arg || *end || value > UINT_MAX ||
		    !value || (value & (value - 1)) || value % getpagesize()) {
			fprintf(stderr, "--user-rb-size must be page-aligned power of two\n");
			argp_usage(state);
		}
		args.user_rb_size = value;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_trigger_batch_argp = {
	.options = opts,
	.parser = parse_arg,
};

/* adjust slot shift in inc_hits() if changing */
#define MAX_BUCKETS 256

#pragma GCC diagnostic ignored "-Wattributes"

/* BPF triggering benchmarks */
static struct trigger_ctx {
	struct trigger_bench *skel;
	struct user_ring_buffer *user_ringbuf;
	bool usermode_counters;
	int driver_prog_fd;
} ctx;

static struct counter base_hits[MAX_BUCKETS];
static struct counter user_ringbuf_enospc;

static __always_inline void inc_counter(struct counter *counters)
{
	static __thread int tid = 0;
	unsigned slot;

	if (unlikely(tid == 0))
		tid = sys_gettid();

	/* multiplicative hashing, it's fast */
	slot = 2654435769U * tid;
	slot >>= 24;

	atomic_inc(&base_hits[slot].value); /* use highest byte as an index */
}

static long sum_and_reset_counters(struct counter *counters)
{
	int i;
	long sum = 0;

	for (i = 0; i < MAX_BUCKETS; i++)
		sum += atomic_swap(&counters[i].value, 0);
	return sum;
}

static void trigger_validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "benchmark doesn't support consumer!\n");
		exit(1);
	}
}

static void trigger_user_ringbuf_validate(void)
{
	trigger_validate();
	if (env.producer_cnt != 1) {
		fprintf(stderr, "benchmark requires exactly one producer!\n");
		exit(1);
	}
}

static void *trigger_producer(void *input)
{
	if (ctx.usermode_counters) {
		while (true) {
			(void)syscall(__NR_getpgid);
			inc_counter(base_hits);
		}
	} else {
		while (true)
			(void)syscall(__NR_getpgid);
	}
	return NULL;
}

static void *trigger_producer_batch(void *input)
{
	int fd = ctx.driver_prog_fd ?: bpf_program__fd(ctx.skel->progs.trigger_driver);

	while (true)
		bpf_prog_test_run_opts(fd, NULL);

	return NULL;
}

static __always_inline __u64 *user_ringbuf_reserve(void)
{
	__u64 *sample;

	while (true) {
		sample = user_ring_buffer__reserve(ctx.user_ringbuf, sizeof(*sample));
		if (sample)
			return sample;
		if (errno == ENOSPC) {
			atomic_inc(&user_ringbuf_enospc.value);
			continue;
		}

		fprintf(stderr, "failed to reserve user ringbuf sample: %s\n",
			strerror(errno));
		exit(1);
	}
}

static void *trigger_user_ringbuf_timer_producer(void *input)
{
	__u64 *sample;

	while (true) {
		sample = user_ringbuf_reserve();
		*sample = 0;
		user_ring_buffer__submit(ctx.user_ringbuf, sample);
	}

	return NULL;
}

static void *trigger_user_ringbuf_syscall_producer(void *input)
{
	__u64 *sample;

	while (true) {
		sample = user_ringbuf_reserve();
		*sample = 0;
		user_ring_buffer__submit(ctx.user_ringbuf, sample);
		(void)syscall(__NR_getppid);
	}

	return NULL;
}

static void trigger_measure(struct bench_res *res)
{
	if (ctx.usermode_counters)
		res->hits = sum_and_reset_counters(base_hits);
	else
		res->hits = sum_and_reset_counters(ctx.skel->bss->hits);
}

static void trigger_user_ringbuf_measure(struct bench_res *res)
{
	trigger_measure(res);
	res->drops = atomic_swap(&user_ringbuf_enospc.value, 0);
}

static void trigger_user_ringbuf_timer_measure(struct bench_res *res)
{
	trigger_user_ringbuf_measure(res);
	res->important_hits = atomic_swap(&ctx.skel->bss->user_ringbuf_timer_fires.value, 0);
}

static void trigger_user_ringbuf_timer_report_progress(int iter, struct bench_res *res,
						       long delta_ns)
{
	double delta_sec = delta_ns / 1000000000.0;

	printf("Iter %3d (%7.3lfus): ", iter,
	       (delta_ns - 1000000000) / 1000.0);
	printf("hits %8.3lfM/s, drops %8.3lfM/s, timer-fires %8.3lfM/s\n",
	       res->hits / 1000000.0 / delta_sec,
	       res->drops / 1000000.0 / delta_sec,
	       res->important_hits / 1000000.0 / delta_sec);
}

static void trigger_user_ringbuf_timer_report_final(struct bench_res res[], int res_cnt)
{
	struct basic_stats hits = {}, enospc = {}, timer_fires = {};
	double value;
	int i;

	for (i = 0; i < res_cnt; i++) {
		hits.mean += res[i].hits / 1000000.0 / res_cnt;
		enospc.mean += res[i].drops / 1000000.0 / res_cnt;
		timer_fires.mean += res[i].important_hits / 1000000.0 / res_cnt;
	}

	if (res_cnt > 1) {
		for (i = 0; i < res_cnt; i++) {
			value = res[i].hits / 1000000.0;
			hits.stddev += (hits.mean - value) * (hits.mean - value) /
				       (res_cnt - 1.0);
			value = res[i].drops / 1000000.0;
			enospc.stddev += (enospc.mean - value) * (enospc.mean - value) /
					 (res_cnt - 1.0);
			value = res[i].important_hits / 1000000.0;
			timer_fires.stddev +=
				(timer_fires.mean - value) * (timer_fires.mean - value) /
				(res_cnt - 1.0);
		}

		hits.stddev = sqrt(hits.stddev);
		enospc.stddev = sqrt(enospc.stddev);
		timer_fires.stddev = sqrt(timer_fires.stddev);
	}

	printf("Summary: hits %8.3lf ± %5.3lfM/s, ", hits.mean, hits.stddev);
	printf("drops %8.3lf ± %5.3lfM/s, ", enospc.mean, enospc.stddev);
	printf("timer-fires %8.3lf ± %5.3lfM/s\n",
	       timer_fires.mean, timer_fires.stddev);
}

static void setup_ctx(void)
{
	setup_libbpf();

	ctx.skel = trigger_bench__open();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	/* default "driver" BPF program */
	bpf_program__set_autoload(ctx.skel->progs.trigger_driver, true);

	ctx.skel->rodata->batch_iters = args.batch_iters;
	ctx.skel->rodata->stacktrace = env.stacktrace;
	ctx.skel->rodata->user_ringbuf_timer_ns = args.user_rb_timer_ns;
	ctx.skel->rodata->user_ringbuf_target_tgid = getpid();
}

static void set_user_ringbuf_size(void)
{
	int err;

	err = bpf_map__set_max_entries(ctx.skel->maps.user_ringbuf,
				       args.user_rb_size);
	if (err) {
		fprintf(stderr, "failed to set user ringbuf size: %s\n",
			strerror(-err));
		exit(1);
	}
}

static void load_ctx(void)
{
	int err;

	err = trigger_bench__load(ctx.skel);
	if (err) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}
}

static void attach_bpf(struct bpf_program *prog)
{
	struct bpf_link *link;

	link = bpf_program__attach(prog);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}
}

static void trigger_syscall_count_setup(void)
{
	ctx.usermode_counters = true;
}

static void setup_user_ringbuf(void)
{
	int map_fd;

	map_fd = bpf_map__fd(ctx.skel->maps.user_ringbuf);
	ctx.user_ringbuf = user_ring_buffer__new(map_fd, NULL);
	if (!ctx.user_ringbuf) {
		fprintf(stderr, "failed to create user ringbuf: %s\n", strerror(errno));
		exit(1);
	}
}

static void trigger_user_ringbuf_timer_setup(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	setup_ctx();
	bpf_program__set_autoload(ctx.skel->progs.trigger_driver, false);
	bpf_program__set_autoload(ctx.skel->progs.trigger_user_ringbuf_timer_init, true);
	set_user_ringbuf_size();
	load_ctx();
	setup_user_ringbuf();

	err = bpf_prog_test_run_opts(
		bpf_program__fd(ctx.skel->progs.trigger_user_ringbuf_timer_init),
		&opts);
	if (err || opts.retval) {
		fprintf(stderr, "failed to start user ringbuf timer: %s (retval %d)\n",
			err ? strerror(errno) : "BPF program error", (__s32)opts.retval);
		exit(1);
	}
}

static void trigger_user_ringbuf_syscall_setup(void)
{
	setup_ctx();
	bpf_program__set_autoload(ctx.skel->progs.trigger_driver, false);
	bpf_program__set_autoload(ctx.skel->progs.trigger_user_ringbuf_syscall, true);
	set_user_ringbuf_size();
	load_ctx();
	setup_user_ringbuf();
	attach_bpf(ctx.skel->progs.trigger_user_ringbuf_syscall);
}

/* Batched, staying mostly in-kernel triggering setups */
static void trigger_kernel_count_setup(void)
{
	setup_ctx();
	bpf_program__set_autoload(ctx.skel->progs.trigger_driver, false);
	bpf_program__set_autoload(ctx.skel->progs.trigger_kernel_count, true);
	load_ctx();
	/* override driver program */
	ctx.driver_prog_fd = bpf_program__fd(ctx.skel->progs.trigger_kernel_count);
}

static void trigger_kprobe_setup(void)
{
	setup_ctx();
	bpf_program__set_autoload(ctx.skel->progs.bench_trigger_kprobe, true);
	load_ctx();
	attach_bpf(ctx.skel->progs.bench_trigger_kprobe);
}

static void trigger_kretprobe_setup(void)
{
	setup_ctx();
	bpf_program__set_autoload(ctx.skel->progs.bench_trigger_kretprobe, true);
	load_ctx();
	attach_bpf(ctx.skel->progs.bench_trigger_kretprobe);
}

static void trigger_kprobe_multi_setup(void)
{
	setup_ctx();
	bpf_program__set_autoload(ctx.skel->progs.bench_trigger_kprobe_multi, true);
	load_ctx();
	attach_bpf(ctx.skel->progs.bench_trigger_kprobe_multi);
}

static void trigger_kretprobe_multi_setup(void)
{
	setup_ctx();
	bpf_program__set_autoload(ctx.skel->progs.bench_trigger_kretprobe_multi, true);
	load_ctx();
	attach_bpf(ctx.skel->progs.bench_trigger_kretprobe_multi);
}

static void trigger_fentry_setup(void)
{
	setup_ctx();
	bpf_program__set_autoload(ctx.skel->progs.bench_trigger_fentry, true);
	load_ctx();
	attach_bpf(ctx.skel->progs.bench_trigger_fentry);
}

static void attach_ksyms_all(struct bpf_program *empty, bool kretprobe)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	struct bpf_link *link = NULL;
	struct ksyms *ksyms = NULL;

	/* Some recursive functions will be skipped in
	 * bpf_get_ksyms -> skip_entry, as they can introduce sufficient
	 * overhead. However, it's difficut to skip all the recursive
	 * functions for a debug kernel.
	 *
	 * So, don't run the kprobe-multi-all and kretprobe-multi-all on
	 * a debug kernel.
	 */
	if (bpf_get_ksyms(&ksyms, true)) {
		fprintf(stderr, "failed to get ksyms\n");
		exit(1);
	}

	opts.syms = (const char **)ksyms->filtered_syms;
	opts.cnt = ksyms->filtered_cnt;
	opts.retprobe = kretprobe;
	/* attach empty to all the kernel functions except bpf_get_numa_node_id. */
	link = bpf_program__attach_kprobe_multi_opts(empty, NULL, &opts);
	free_kallsyms_local(ksyms);
	if (!link) {
		fprintf(stderr, "failed to attach bpf_program__attach_kprobe_multi_opts to all\n");
		exit(1);
	}
}

static void trigger_kprobe_multi_all_setup(void)
{
	struct bpf_program *prog, *empty;

	setup_ctx();
	empty = ctx.skel->progs.bench_kprobe_multi_empty;
	prog = ctx.skel->progs.bench_trigger_kprobe_multi;
	bpf_program__set_autoload(empty, true);
	bpf_program__set_autoload(prog, true);
	load_ctx();

	attach_ksyms_all(empty, false);
	attach_bpf(prog);
}

static void trigger_kretprobe_multi_all_setup(void)
{
	struct bpf_program *prog, *empty;

	setup_ctx();
	empty = ctx.skel->progs.bench_kretprobe_multi_empty;
	prog = ctx.skel->progs.bench_trigger_kretprobe_multi;
	bpf_program__set_autoload(empty, true);
	bpf_program__set_autoload(prog, true);
	load_ctx();

	attach_ksyms_all(empty, true);
	attach_bpf(prog);
}

static void trigger_fexit_setup(void)
{
	setup_ctx();
	bpf_program__set_autoload(ctx.skel->progs.bench_trigger_fexit, true);
	load_ctx();
	attach_bpf(ctx.skel->progs.bench_trigger_fexit);
}

static void trigger_fmodret_setup(void)
{
	setup_ctx();
	bpf_program__set_autoload(ctx.skel->progs.trigger_driver, false);
	bpf_program__set_autoload(ctx.skel->progs.trigger_driver_kfunc, true);
	bpf_program__set_autoload(ctx.skel->progs.bench_trigger_fmodret, true);
	load_ctx();
	/* override driver program */
	ctx.driver_prog_fd = bpf_program__fd(ctx.skel->progs.trigger_driver_kfunc);
	attach_bpf(ctx.skel->progs.bench_trigger_fmodret);
}

static void trigger_tp_setup(void)
{
	setup_ctx();
	bpf_program__set_autoload(ctx.skel->progs.trigger_driver, false);
	bpf_program__set_autoload(ctx.skel->progs.trigger_driver_kfunc, true);
	bpf_program__set_autoload(ctx.skel->progs.bench_trigger_tp, true);
	load_ctx();
	/* override driver program */
	ctx.driver_prog_fd = bpf_program__fd(ctx.skel->progs.trigger_driver_kfunc);
	attach_bpf(ctx.skel->progs.bench_trigger_tp);
}

static void trigger_rawtp_setup(void)
{
	setup_ctx();
	bpf_program__set_autoload(ctx.skel->progs.trigger_driver, false);
	bpf_program__set_autoload(ctx.skel->progs.trigger_driver_kfunc, true);
	bpf_program__set_autoload(ctx.skel->progs.bench_trigger_rawtp, true);
	load_ctx();
	/* override driver program */
	ctx.driver_prog_fd = bpf_program__fd(ctx.skel->progs.trigger_driver_kfunc);
	attach_bpf(ctx.skel->progs.bench_trigger_rawtp);
}

/* make sure call is not inlined and not avoided by compiler, so __weak and
 * inline asm volatile in the body of the function
 *
 * There is a performance difference between uprobing at nop location vs other
 * instructions. So use two different targets, one of which starts with nop
 * and another doesn't.
 *
 * GCC doesn't generate stack setup preamble for these functions due to them
 * having no input arguments and doing nothing in the body.
 */
__nocf_check __weak void uprobe_target_nop(void)
{
	asm volatile ("nop");
}

__weak void opaque_noop_func(void)
{
}

__nocf_check __weak int uprobe_target_push(void)
{
	/* overhead of function call is negligible compared to uprobe
	 * triggering, so this shouldn't affect benchmark results much
	 */
	opaque_noop_func();
	return 1;
}

__nocf_check __weak void uprobe_target_ret(void)
{
	asm volatile ("");
}

static void *uprobe_producer_count(void *input)
{
	while (true) {
		uprobe_target_nop();
		inc_counter(base_hits);
	}
	return NULL;
}

static void *uprobe_producer_nop(void *input)
{
	while (true)
		uprobe_target_nop();
	return NULL;
}

static void *uprobe_producer_push(void *input)
{
	while (true)
		uprobe_target_push();
	return NULL;
}

static void *uprobe_producer_ret(void *input)
{
	while (true)
		uprobe_target_ret();
	return NULL;
}

#ifdef __x86_64__
__nocf_check __weak void uprobe_target_nop10(void)
{
	asm volatile (".byte 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00");
}

static void *uprobe_producer_nop10(void *input)
{
	while (true)
		uprobe_target_nop10();
	return NULL;
}

void usdt_1(void);
void usdt_2(void);

static void *uprobe_producer_usdt_nop(void *input)
{
	while (true)
		usdt_1();
	return NULL;
}

static void *uprobe_producer_usdt_nop10(void *input)
{
	while (true)
		usdt_2();
	return NULL;
}
#endif

static void usetup(bool use_retprobe, bool use_multi, void *target_addr)
{
	size_t uprobe_offset;
	struct bpf_link *link;
	int err;

	setup_libbpf();

	ctx.skel = trigger_bench__open();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	if (use_multi)
		bpf_program__set_autoload(ctx.skel->progs.bench_trigger_uprobe_multi, true);
	else
		bpf_program__set_autoload(ctx.skel->progs.bench_trigger_uprobe, true);

	err = trigger_bench__load(ctx.skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		exit(1);
	}

	uprobe_offset = get_uprobe_offset(target_addr);
	if (use_multi) {
		LIBBPF_OPTS(bpf_uprobe_multi_opts, opts,
			.retprobe = use_retprobe,
			.cnt = 1,
			.offsets = &uprobe_offset,
		);
		link = bpf_program__attach_uprobe_multi(
			ctx.skel->progs.bench_trigger_uprobe_multi,
			-1 /* all PIDs */, "/proc/self/exe", NULL, &opts);
		ctx.skel->links.bench_trigger_uprobe_multi = link;
	} else {
		link = bpf_program__attach_uprobe(ctx.skel->progs.bench_trigger_uprobe,
						  use_retprobe,
						  -1 /* all PIDs */,
						  "/proc/self/exe",
						  uprobe_offset);
		ctx.skel->links.bench_trigger_uprobe = link;
	}
	if (!link) {
		fprintf(stderr, "failed to attach %s!\n", use_multi ? "multi-uprobe" : "uprobe");
		exit(1);
	}
}

static void usermode_count_setup(void)
{
	ctx.usermode_counters = true;
}

static void uprobe_nop_setup(void)
{
	usetup(false, false /* !use_multi */, &uprobe_target_nop);
}

static void uretprobe_nop_setup(void)
{
	usetup(true, false /* !use_multi */, &uprobe_target_nop);
}

static void uprobe_push_setup(void)
{
	usetup(false, false /* !use_multi */, &uprobe_target_push);
}

static void uretprobe_push_setup(void)
{
	usetup(true, false /* !use_multi */, &uprobe_target_push);
}

static void uprobe_ret_setup(void)
{
	usetup(false, false /* !use_multi */, &uprobe_target_ret);
}

static void uretprobe_ret_setup(void)
{
	usetup(true, false /* !use_multi */, &uprobe_target_ret);
}

static void uprobe_multi_nop_setup(void)
{
	usetup(false, true /* use_multi */, &uprobe_target_nop);
}

static void uretprobe_multi_nop_setup(void)
{
	usetup(true, true /* use_multi */, &uprobe_target_nop);
}

static void uprobe_multi_push_setup(void)
{
	usetup(false, true /* use_multi */, &uprobe_target_push);
}

static void uretprobe_multi_push_setup(void)
{
	usetup(true, true /* use_multi */, &uprobe_target_push);
}

static void uprobe_multi_ret_setup(void)
{
	usetup(false, true /* use_multi */, &uprobe_target_ret);
}

static void uretprobe_multi_ret_setup(void)
{
	usetup(true, true /* use_multi */, &uprobe_target_ret);
}

#ifdef __x86_64__
static void uprobe_nop10_setup(void)
{
	usetup(false, false /* !use_multi */, &uprobe_target_nop10);
}

static void uretprobe_nop10_setup(void)
{
	usetup(true, false /* !use_multi */, &uprobe_target_nop10);
}

static void uprobe_multi_nop10_setup(void)
{
	usetup(false, true /* use_multi */, &uprobe_target_nop10);
}

static void uretprobe_multi_nop10_setup(void)
{
	usetup(true, true /* use_multi */, &uprobe_target_nop10);
}

static void usdt_setup(const char *name)
{
	struct bpf_link *link;
	int err;

	setup_libbpf();

	ctx.skel = trigger_bench__open();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	bpf_program__set_autoload(ctx.skel->progs.bench_trigger_usdt, true);

	err = trigger_bench__load(ctx.skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		exit(1);
	}

	link = bpf_program__attach_usdt(ctx.skel->progs.bench_trigger_usdt,
					0 /*self*/, "/proc/self/exe",
					"optimized_attach", name, NULL);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "failed to attach optimized_attach:%s usdt probe\n", name);
		exit(1);
	}
	ctx.skel->links.bench_trigger_usdt = link;
}

static void usdt_nop_setup(void)
{
	usdt_setup("usdt_1");
}

static void usdt_nop10_setup(void)
{
	usdt_setup("usdt_2");
}
#endif

const struct bench bench_trig_syscall_count = {
	.name = "trig-syscall-count",
	.validate = trigger_validate,
	.setup = trigger_syscall_count_setup,
	.producer_thread = trigger_producer,
	.measure = trigger_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_trig_user_ringbuf_timer = {
	.name = "trig-user-ringbuf-timer",
	.validate = trigger_user_ringbuf_validate,
	.setup = trigger_user_ringbuf_timer_setup,
	.producer_thread = trigger_user_ringbuf_timer_producer,
	.measure = trigger_user_ringbuf_timer_measure,
	.report_progress = trigger_user_ringbuf_timer_report_progress,
	.report_final = trigger_user_ringbuf_timer_report_final,
	.argp = &bench_trigger_batch_argp,
};

const struct bench bench_trig_user_ringbuf_syscall = {
	.name = "trig-user-ringbuf-syscall",
	.validate = trigger_user_ringbuf_validate,
	.setup = trigger_user_ringbuf_syscall_setup,
	.producer_thread = trigger_user_ringbuf_syscall_producer,
	.measure = trigger_user_ringbuf_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

/* batched (staying mostly in kernel) kprobe/fentry benchmarks */
#define BENCH_TRIG_KERNEL(KIND, NAME)					\
const struct bench bench_trig_##KIND = {				\
	.name = "trig-" NAME,						\
	.setup = trigger_##KIND##_setup,				\
	.producer_thread = trigger_producer_batch,			\
	.measure = trigger_measure,					\
	.report_progress = hits_drops_report_progress,			\
	.report_final = hits_drops_report_final,			\
	.argp = &bench_trigger_batch_argp,				\
}

BENCH_TRIG_KERNEL(kernel_count, "kernel-count");
BENCH_TRIG_KERNEL(kprobe, "kprobe");
BENCH_TRIG_KERNEL(kretprobe, "kretprobe");
BENCH_TRIG_KERNEL(kprobe_multi, "kprobe-multi");
BENCH_TRIG_KERNEL(kretprobe_multi, "kretprobe-multi");
BENCH_TRIG_KERNEL(fentry, "fentry");
BENCH_TRIG_KERNEL(kprobe_multi_all, "kprobe-multi-all");
BENCH_TRIG_KERNEL(kretprobe_multi_all, "kretprobe-multi-all");
BENCH_TRIG_KERNEL(fexit, "fexit");
BENCH_TRIG_KERNEL(fmodret, "fmodret");
BENCH_TRIG_KERNEL(tp, "tp");
BENCH_TRIG_KERNEL(rawtp, "rawtp");

/* uprobe benchmarks */
#define BENCH_TRIG_USERMODE(KIND, PRODUCER, NAME)			\
const struct bench bench_trig_##KIND = {				\
	.name = "trig-" NAME,						\
	.validate = trigger_validate,					\
	.setup = KIND##_setup,						\
	.producer_thread = uprobe_producer_##PRODUCER,			\
	.measure = trigger_measure,					\
	.report_progress = hits_drops_report_progress,			\
	.report_final = hits_drops_report_final,			\
}

BENCH_TRIG_USERMODE(usermode_count, count, "usermode-count");
BENCH_TRIG_USERMODE(uprobe_nop, nop, "uprobe-nop");
BENCH_TRIG_USERMODE(uprobe_push, push, "uprobe-push");
BENCH_TRIG_USERMODE(uprobe_ret, ret, "uprobe-ret");
BENCH_TRIG_USERMODE(uretprobe_nop, nop, "uretprobe-nop");
BENCH_TRIG_USERMODE(uretprobe_push, push, "uretprobe-push");
BENCH_TRIG_USERMODE(uretprobe_ret, ret, "uretprobe-ret");
BENCH_TRIG_USERMODE(uprobe_multi_nop, nop, "uprobe-multi-nop");
BENCH_TRIG_USERMODE(uprobe_multi_push, push, "uprobe-multi-push");
BENCH_TRIG_USERMODE(uprobe_multi_ret, ret, "uprobe-multi-ret");
BENCH_TRIG_USERMODE(uretprobe_multi_nop, nop, "uretprobe-multi-nop");
BENCH_TRIG_USERMODE(uretprobe_multi_push, push, "uretprobe-multi-push");
BENCH_TRIG_USERMODE(uretprobe_multi_ret, ret, "uretprobe-multi-ret");
#ifdef __x86_64__
BENCH_TRIG_USERMODE(uprobe_nop10, nop10, "uprobe-nop10");
BENCH_TRIG_USERMODE(uretprobe_nop10, nop10, "uretprobe-nop10");
BENCH_TRIG_USERMODE(uprobe_multi_nop10, nop10, "uprobe-multi-nop10");
BENCH_TRIG_USERMODE(uretprobe_multi_nop10, nop10, "uretprobe-multi-nop10");
BENCH_TRIG_USERMODE(usdt_nop, usdt_nop, "usdt-nop");
BENCH_TRIG_USERMODE(usdt_nop10, usdt_nop10, "usdt-nop10");
#endif
