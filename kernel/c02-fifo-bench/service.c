// SPDX-License-Identifier: GPL-2.0
#include "fifo-bench.h"

#if FIFO_VARIANT == 3 || FIFO_VARIANT == 4
static inline unsigned int fifo_private(struct __kfifo *fifo, unsigned int *tail, unsigned int n)
#include "body.inc"
#define __kfifo_out_linear fifo_private
#elif FIFO_VARIANT == 1 || FIFO_VARIANT == 2
#define __kfifo_out_linear fifo_boundary
#elif FIFO_VARIANT != 0
#error Unsupported FIFO_VARIANT
#endif

static __always_inline unsigned int select_span(struct kfifo *fifo, u8 **tail, unsigned int space)
{
	return kfifo_out_linear_ptr(fifo, tail, space);
}

unsigned int fifo_span(struct kfifo *fifo, u8 **tail, unsigned int space)
{
	return select_span(fifo, tail, space);
}

unsigned int fifo_service(struct kfifo *fifo, u8 *sink, unsigned int space)
{
	unsigned int n;
	u8 *tail;

	if (kfifo_is_empty(fifo))
		return 0;
	n = select_span(fifo, &tail, space);
	memcpy(sink, tail, n);
	kfifo_skip_count(fifo, n);
	return n;
}
