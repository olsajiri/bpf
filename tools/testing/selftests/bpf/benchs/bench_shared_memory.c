// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Jiri Olsa */
#define _GNU_SOURCE
#include <argp.h>
#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/types.h>
#include "bench.h"

#define SHARED_MEMORY_CACHELINE 64
#define SHARED_MEMORY_EVENT_SIZE_DEFAULT 432
#define SHARED_MEMORY_EVENT_SIZE_MIN 8
#define SHARED_MEMORY_SIZE_DEFAULT (4 * 1024 * 1024)

#define MSG_OP_JAVA 29

struct shared_memory_index {
	uint64_t pos;
	char pad[SHARED_MEMORY_CACHELINE - sizeof(uint64_t)];
};

struct shared_memory_ring {
	uint64_t magic;
	uint32_t event_size;
	uint32_t slot_count;
	char pad[SHARED_MEMORY_CACHELINE - sizeof(uint64_t) -
		 sizeof(uint32_t) - sizeof(uint32_t)];
	struct shared_memory_index producer;
	struct shared_memory_index consumer;
	unsigned char data[];
};

_Static_assert(sizeof(struct shared_memory_index) == SHARED_MEMORY_CACHELINE,
	       "shared memory index must occupy one cacheline");
_Static_assert(offsetof(struct shared_memory_ring, data) % SHARED_MEMORY_CACHELINE == 0,
	       "shared memory data must be cacheline aligned");

static struct {
	size_t size;
	__u32 event_size;
} args = {
	.size = SHARED_MEMORY_SIZE_DEFAULT,
	.event_size = SHARED_MEMORY_EVENT_SIZE_DEFAULT,
};

enum {
	ARG_SHARED_MEMORY_SIZE = 7100,
	ARG_SHARED_MEMORY_EVENT_SIZE,
};

static const struct argp_option opts[] = {
	{ "shared-mem-size", ARG_SHARED_MEMORY_SIZE, "BYTES", 0,
		"Shared memory ring size in bytes"},
	{ "shared-mem-event-size", ARG_SHARED_MEMORY_EVENT_SIZE, "BYTES", 0,
		"Shared memory event size in bytes"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	unsigned long long value;
	char *end;

	switch (key) {
	case ARG_SHARED_MEMORY_SIZE:
		errno = 0;
		value = strtoull(arg, &end, 10);
		if (errno || end == arg || *end || arg[0] == '-' ||
		    value < (unsigned long long)getpagesize() || value > UINT_MAX ||
		    (value & (value - 1)) || value % getpagesize()) {
			fprintf(stderr,
				"--shared-mem-size must be page-aligned power of two\n");
			argp_usage(state);
		}
		args.size = value;
		break;
	case ARG_SHARED_MEMORY_EVENT_SIZE:
		errno = 0;
		value = strtoull(arg, &end, 10);
		if (errno || end == arg || *end || arg[0] == '-' ||
		    value < SHARED_MEMORY_EVENT_SIZE_MIN || value > UINT_MAX) {
			fprintf(stderr,
				"--shared-mem-event-size must be at least %d bytes\n",
				SHARED_MEMORY_EVENT_SIZE_MIN);
			argp_usage(state);
		}
		args.event_size = value;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

struct argp bench_shared_memory_argp = {
	.options = opts,
	.parser = parse_arg,
};

static struct {
	struct shared_memory_ring *ring;
	size_t map_size;
	__u32 slot_count;
	__u32 event_size;
	int eventfd;
	bool notify;
	bool consumer_waiting;
	long hits;
	long drops;
} ctx = {
	.eventfd = -1,
};

static void shared_memory_fail(const char *op)
{
	fprintf(stderr, "%s failed: %s\n", op, strerror(errno));
	exit(1);
}

static void shared_memory_validate(void)
{
	if (env.producer_cnt != 1 || env.consumer_cnt != 1) {
		fprintf(stderr,
			"benchmark requires exactly one producer and one consumer\n");
		exit(1);
	}
	if (args.size / args.event_size == 0) {
		fprintf(stderr, "shared memory ring is too small for one event\n");
		exit(1);
	}
	if (args.size / args.event_size > UINT_MAX) {
		fprintf(stderr, "shared memory ring has too many slots\n");
		exit(1);
	}
	if (args.size > SIZE_MAX - offsetof(struct shared_memory_ring, data)) {
		fprintf(stderr, "shared memory ring size is too large\n");
		exit(1);
	}
}

static void shared_memory_setup(bool notify)
{
	size_t max_slots;
	size_t data_size;

	ctx.event_size = args.event_size;
	max_slots = args.size / args.event_size;
	ctx.slot_count = 1U << (63 - __builtin_clzll(max_slots));
	data_size = (size_t)ctx.slot_count * ctx.event_size;
	ctx.map_size = offsetof(struct shared_memory_ring, data) + data_size;
	ctx.ring = mmap(NULL, ctx.map_size, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ctx.ring == MAP_FAILED)
		shared_memory_fail("mmap");

	ctx.ring->magic = 0x5348504352494e47ULL;
	ctx.ring->event_size = ctx.event_size;
	ctx.ring->slot_count = ctx.slot_count;
	ctx.notify = notify;
	if (notify) {
		ctx.eventfd = eventfd(0, EFD_CLOEXEC);
		if (ctx.eventfd < 0)
			shared_memory_fail("eventfd");
	}
}

static inline unsigned char *shared_memory_slot(uint64_t pos)
{
	return ctx.ring->data +
		(pos & (ctx.slot_count - 1)) * ctx.event_size;
}

static void shared_memory_busy_setup(void)
{
	shared_memory_setup(false);
}

static void shared_memory_eventfd_setup(void)
{
	shared_memory_setup(true);
}

static void shared_memory_notify(void)
{
	while (eventfd_write(ctx.eventfd, 1)) {
		if (errno != EINTR)
			shared_memory_fail("eventfd_write");
	}
}

static void *shared_memory_producer(void *input)
{
	__u32 record_size = htole32(ctx.event_size);
	char *event;

	(void)input;
	event = calloc(1, ctx.event_size);
	if (!event)
		shared_memory_fail("calloc");
	event[0] = MSG_OP_JAVA;
	memcpy(event + 4, &record_size, sizeof(record_size));

	while (true) {
		uint64_t producer, consumer;
		bool was_empty;
		unsigned char *slot;

		producer = __atomic_load_n(&ctx.ring->producer.pos, __ATOMIC_RELAXED);
		consumer = __atomic_load_n(&ctx.ring->consumer.pos, __ATOMIC_ACQUIRE);
		if (producer - consumer >= ctx.slot_count) {
			atomic_inc(&ctx.drops);
			continue;
		}
		was_empty = producer == consumer;

		slot = shared_memory_slot(producer);
		memcpy(slot, event, ctx.event_size);
		__atomic_store_n(&ctx.ring->producer.pos, producer + 1,
				 __ATOMIC_RELEASE);

		if (ctx.notify) {
			bool consumer_waiting;

			consumer_waiting = __atomic_exchange_n(&ctx.consumer_waiting, false,
							      __ATOMIC_ACQ_REL);
			/* Wake a sleeping consumer, or publish an empty-to-nonempty edge. */
			if (was_empty || consumer_waiting)
				shared_memory_notify();
		}
	}

	return NULL;
}

static void shared_memory_wait(void)
{
	eventfd_t value;

	while (eventfd_read(ctx.eventfd, &value)) {
		if (errno != EINTR)
			shared_memory_fail("eventfd_read");
	}
}

static void *shared_memory_consumer(void *input)
{
	(void)input;

	while (true) {
		uint64_t consumer, producer;

		consumer = __atomic_load_n(&ctx.ring->consumer.pos, __ATOMIC_RELAXED);
		producer = __atomic_load_n(&ctx.ring->producer.pos, __ATOMIC_ACQUIRE);
		while (consumer != producer) {
			unsigned char *slot;
			__u32 record_size;

			slot = shared_memory_slot(consumer);
			memcpy(&record_size, slot + 4, sizeof(record_size));
			if (slot[0] == MSG_OP_JAVA &&
			    le32toh(record_size) == ctx.event_size)
				atomic_inc(&ctx.hits);
			else
				atomic_inc(&ctx.drops);
			consumer++;
		}
		__atomic_store_n(&ctx.ring->consumer.pos, consumer, __ATOMIC_RELEASE);

		if (ctx.notify &&
		    __atomic_load_n(&ctx.ring->producer.pos, __ATOMIC_ACQUIRE) == consumer) {
			__atomic_store_n(&ctx.consumer_waiting, true, __ATOMIC_RELEASE);
			if (__atomic_load_n(&ctx.ring->producer.pos, __ATOMIC_ACQUIRE) == consumer)
				shared_memory_wait();
			__atomic_store_n(&ctx.consumer_waiting, false, __ATOMIC_RELEASE);
		}
	}

	return NULL;
}

static void shared_memory_measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.hits, 0);
	res->drops = atomic_swap(&ctx.drops, 0);
}

const struct bench bench_trig_shared_memory = {
	.name = "trig-shared-memory",
	.validate = shared_memory_validate,
	.setup = shared_memory_busy_setup,
	.producer_thread = shared_memory_producer,
	.consumer_thread = shared_memory_consumer,
	.measure = shared_memory_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
	.argp = &bench_shared_memory_argp,
};

const struct bench bench_trig_shared_memory_eventfd = {
	.name = "trig-shared-memory-eventfd",
	.validate = shared_memory_validate,
	.setup = shared_memory_eventfd_setup,
	.producer_thread = shared_memory_producer,
	.consumer_thread = shared_memory_consumer,
	.measure = shared_memory_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
	.argp = &bench_shared_memory_argp,
};
