// SPDX-License-Identifier: GPL-2.0
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "fifo-bench.h"

#define RING_SIZE 4096U
#define INITIAL_OUT (UINT_MAX - 17U)
static const unsigned int space_pattern[] = {1, 8, 31, 64, 7, 32, 63, 16};
static unsigned int calls = 100000;
static bool local_only;
static unsigned int cpu_start, cpu_end, out_end, in_end;
static unsigned long elapsed_ns, transferred, offset_sum;
module_param(calls, uint, 0444);
module_param(local_only, bool, 0444);
module_param(cpu_start, uint, 0444);
module_param(cpu_end, uint, 0444);
module_param(out_end, uint, 0444);
module_param(in_end, uint, 0444);
module_param(elapsed_ns, ulong, 0444);
module_param(transferred, ulong, 0444);
module_param(offset_sum, ulong, 0444);

static unsigned int compiled_variant = FIFO_VARIANT;
module_param(compiled_variant, uint, 0444);

static u8 pattern(unsigned int cursor)
{
	unsigned int offset = cursor % RING_SIZE;

	return (offset * 29 + (offset >> 8) * 13 + 7) & 255;
}

static int exercise_edges(struct kfifo *fifo, u8 *sink)
{
	unsigned int i;
	struct __kfifo tmp = fifo->kfifo;

	/* Unknown outputs stay on the public kernel entry, including a true alias. */
	tmp.mask = 7;
	tmp.in = 10;
	tmp.out = 9;
	if (__kfifo_out_linear(&tmp, NULL, 8) != 1 ||
	    __kfifo_out_linear(&tmp, &tmp.out, 8) != 7 || tmp.out != 1)
		return -EINVAL;
	if (fifo_service(fifo, sink, 31) || fifo->kfifo.out)
		return -EINVAL;
	fifo->kfifo.out = UINT_MAX - 1;
	fifo->kfifo.in = 1;
	if (fifo_service(fifo, sink, 31) != 2 || fifo->kfifo.out != 0)
		return -EINVAL;
	for (i = 0; i < 2; i++)
		if (sink[i] != pattern(UINT_MAX - 1 + i))
			return -EINVAL;
	if (fifo_service(fifo, sink, 31) != 1 || sink[0] != pattern(0) || fifo->kfifo.out != 1)
		return -EINVAL;
	return 0;
}

static int measure(struct kfifo *fifo, u8 *sink)
{
	unsigned int i, cursor = INITIAL_OUT;
	unsigned long count = 0, offsets = 0;
	u64 start;

	fifo->kfifo.out = INITIAL_OUT;
	fifo->kfifo.in = INITIAL_OUT + RING_SIZE;
	cpu_start = raw_smp_processor_id();
	start = ktime_get_ns();
	for (i = 0; i < calls; i++) {
		unsigned int space = space_pattern[i % ARRAY_SIZE(space_pattern)];
		unsigned int n;

		if (local_only) {
			u8 *tail;

			n = fifo_span(fifo, &tail, space);
			offset_sum += tail - (u8 *)fifo->kfifo.data;
			kfifo_skip_count(fifo, n);
		} else {
			n = fifo_service(fifo, sink + transferred, space);
		}
		transferred += n;
		/* The private producer repeats the resident byte stream each lap. */
		fifo->kfifo.in += n;
	}
	elapsed_ns = ktime_get_ns() - start;
	cpu_end = raw_smp_processor_id();
	out_end = fifo->kfifo.out;
	in_end = fifo->kfifo.in;
	for (i = 0; i < calls; i++) {
		unsigned int offset = cursor % RING_SIZE;
		unsigned int span = min(space_pattern[i % ARRAY_SIZE(space_pattern)], RING_SIZE - offset);

		count += span;
		offsets += offset;
		cursor += span;
	}
	if (count != transferred || out_end != cursor || in_end != cursor + RING_SIZE ||
	    !elapsed_ns || cpu_start != cpu_end)
		return -EINVAL;
	if (local_only)
		return offsets == offset_sum ? 0 : -EINVAL;
	for (i = 0; i < count; i++)
		if (sink[i] != pattern(INITIAL_OUT + i))
			return -EINVAL;
	return 0;
}

static int __init fifo_bench_init(void)
{
	struct kfifo fifo;
	unsigned int i;
	int rc;
	u8 *sink;

	if (calls == 0 || calls > 100000)
		return -EINVAL;
	rc = kfifo_alloc(&fifo, RING_SIZE, GFP_KERNEL);
	if (rc)
		return rc;
	sink = kvmalloc_array(calls, 64, GFP_KERNEL);
	if (!sink) {
		rc = -ENOMEM;
		goto release_fifo;
	}
	memset(sink, 0xcc, calls * 64);
	for (i = 0; i < RING_SIZE; i++)
		((u8 *)fifo.kfifo.data)[i] = pattern(i);
	rc = exercise_edges(&fifo, sink);
	if (!rc)
		rc = measure(&fifo, sink);
	/* The init task owns both allocations; no worker or callback observes them. */
	kvfree(sink);
release_fifo:
	kfifo_free(&fifo);
	return rc;
}

static void __exit fifo_bench_exit(void) {}
module_init(fifo_bench_init);
module_exit(fifo_bench_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Controlled byte FIFO transmit benchmark");
