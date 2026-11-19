/* SPDX-License-Identifier: GPL-2.0 */
/* Derived from Linux lib/kfifo.c, __kfifo_out_linear, at 2fc2e45b0cd7.
 * Include this body at either call boundary so both comparisons use the same C.
 */
{
	unsigned int size = fifo->mask + 1;
#if FIFO_VARIANT == 2 || FIFO_VARIANT == 4
	unsigned int saved_out = fifo->out;
	unsigned int off = saved_out & fifo->mask;

	if (tail)
		*tail = off;

	return min3(n, fifo->in - saved_out, size - off);
#else
	unsigned int off = fifo->out & fifo->mask;

	if (tail)
		*tail = off;

	return min3(n, fifo->in - fifo->out, size - off);
#endif
}
