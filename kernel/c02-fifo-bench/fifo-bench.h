/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/kfifo.h>

/* Variant numbers correspond to the five Kbuild comparison objects. */
unsigned int fifo_service(struct kfifo *fifo, u8 *sink, unsigned int space);
unsigned int fifo_span(struct kfifo *fifo, u8 **tail, unsigned int space);
unsigned int fifo_boundary(struct __kfifo *fifo, unsigned int *tail, unsigned int n);
