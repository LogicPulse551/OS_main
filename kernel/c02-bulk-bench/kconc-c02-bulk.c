// SPDX-License-Identifier: GPL-2.0-only
/*
 * Measure one six-byte XYZ read through regmap. The transport reproduces
 * the BMA400 SPI register framing and two-byte payload limit from Linux's
 * bma400_spi.c (Dan Robertson, 2020). Bytes are supplied from local memory.
 */
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include "internal.h"

#define FIRST_REG 0x04
#define READ_FLAG BIT(7)
#define BYTES 6
#define TRANSFERS 3
#define MAX_BATCHES 32

static char *mode = "check";
static unsigned int calls = 131072, samples = 3, warmups = 2;
module_param(mode, charp, 0);
module_param(calls, uint, 0);
module_param(samples, uint, 0);
module_param(warmups, uint, 0);

static const u8 payload[BYTES] = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc };
static const int errors[TRANSFERS + 1] = { 0, -EIO, -ETIMEDOUT, -EREMOTEIO };

struct check {
	unsigned int bits, fail_at, transfers;
	int rc, result;
	u8 wire[TRANSFERS], lengths[TRANSFERS], data[BYTES];
	void (*converter)(void *);
};

struct transport {
	unsigned int value_bytes;
	u64 reads;
	struct check *check;
};

struct batch {
	unsigned int sample, warmup, cycles, cpu_start, cpu_end;
	u64 elapsed_ns, bus_reads;
	int result;
};

static struct check checks[2 * (1 + TRANSFERS)];
static struct batch rows[MAX_BATCHES];
static unsigned int check_count, row_count;
static struct dentry *dir;

static bool sample_volatile(struct device *dev, unsigned int reg)
{
	return reg >= FIRST_REG && reg < FIRST_REG + BYTES;
}

static int transport_read(void *context, const void *cmd, size_t cmd_len,
			  void *data, size_t len)
{
	struct transport *t = context;
	unsigned int command, offset;

	t->reads++;
	if (cmd_len != 1 || len != 2)
		return -EINVAL;
	command = *(const u8 *)cmd;
	if (command < (READ_FLAG | FIRST_REG))
		return -ERANGE;
	offset = (command - (READ_FLAG | FIRST_REG)) * t->value_bytes;
	if (offset > BYTES - 2)
		return -ERANGE;
	memcpy(data, payload + offset, 2);
	return 0;
}

/* Count even the transaction that returned the injected bus error. Keep its
 * destination untouched, just as the SPI callback does on a failed read.
 */
static int checked_read(void *context, const void *cmd, size_t cmd_len,
			void *data, size_t len)
{
	struct transport *t = context;
	struct check *c = t->check;
	unsigned int i;

	if (!c)
		return -EIO;
	i = c->transfers++;
	if (i >= TRANSFERS || cmd_len != 1 || len != 2)
		return -EINVAL;
	c->wire[i] = *(const u8 *)cmd;
	c->lengths[i] = len;
	if (c->fail_at == i + 1)
		return errors[i + 1];
	return transport_read(t, cmd, cmd_len, data, len);
}

/* Both bus methods are needed for regmap to select its raw transfer path. */
static int transport_write(void *context, const void *data, size_t len)
{
	return -EOPNOTSUPP;
}

static const struct regmap_bus measurement_bus = {
	.read = transport_read, .write = transport_write,
	.read_flag_mask = READ_FLAG, .max_raw_read = 2,
};
static const struct regmap_bus check_bus = {
	.read = checked_read, .write = transport_write,
	.read_flag_mask = READ_FLAG, .max_raw_read = 2,
};

static struct regmap *open_map(struct transport *t, bool checking)
{
	const struct regmap_config config = {
		.name = "c02-bulk", .reg_bits = 8, .val_bits = t->value_bytes * 8,
		.max_register = 0x7e, .cache_type = REGCACHE_MAPLE,
		.volatile_reg = sample_volatile, .val_format_endian = REGMAP_ENDIAN_BIG,
	};

	return regmap_init(NULL, checking ? &check_bus : &measurement_bus, t, &config);
}

static int check_read(struct regmap *map, struct transport *t, unsigned int fail_at)
{
	struct check *c = &checks[check_count++];
	u8 expected[BYTES];
	unsigned int i, count = fail_at ? fail_at : TRANSFERS;
	unsigned int copied = fail_at ? 2 * (fail_at - 1) : BYTES;

	t->check = c;
	c->bits = t->value_bytes * 8;
	c->converter = map->format.parse_inplace;
	c->fail_at = fail_at;
	memset(c->data, 0xcc, BYTES);
	memset(expected, 0xcc, BYTES);
	memcpy(expected, payload, copied);
	/* regmap parses only after all transfers succeed. This also checks that a
	 * 16-bit partial prefix remains in bus byte order when a later read fails.
	 */
	if (!fail_at && t->value_bytes == 2) {
		for (i = 0; i < BYTES; i += 2) {
			u16 native = ((u16)payload[i] << 8) | payload[i + 1];

			memcpy(expected + i, &native, sizeof(native));
		}
	}
	c->rc = regmap_bulk_read(map, FIRST_REG, c->data, BYTES / t->value_bytes);
	if (c->rc != errors[fail_at] || c->transfers != count ||
	    !c->converter || memcmp(c->data, expected, BYTES))
		c->result = -EIO;
	for (i = 0; i < count; i++) {
		if (c->wire[i] != (READ_FLAG | (FIRST_REG + i * 2 / t->value_bytes)) ||
		    c->lengths[i] != 2)
			c->result = -EIO;
	}
	if (c->result)
		pr_err("c02-bulk check bits=%u fail_at=%u rc=%d transfers=%u wire=%3phN lengths=%3phN data=%6phN\n",
		       c->bits, fail_at, c->rc, c->transfers, c->wire, c->lengths, c->data);
	return c->result;
}

static int run_checks(void)
{
	unsigned int width, fail_at;
	int ret = 0;

	for (width = 1; width <= 2; width++) {
		struct transport t = { .value_bytes = width };
		struct regmap *map = open_map(&t, true);

		if (IS_ERR(map))
			return PTR_ERR(map);
		for (fail_at = 0; fail_at <= TRANSFERS; fail_at++)
			if (check_read(map, &t, fail_at))
				ret = -EIO;
		regmap_exit(map);
	}
	return ret;
}

static int run_batch(struct regmap *map, struct transport *t, bool raw,
		     struct batch *r)
{
	u8 data[BYTES] = {};
	u64 start, reads = t->reads;
	unsigned int i;

	r->cpu_start = raw_smp_processor_id();
	start = ktime_get_ns();
	for (i = 0; i < calls; i++) {
		if (raw)
			r->result = regmap_raw_read(map, FIRST_REG, data, BYTES);
		else
			r->result = regmap_bulk_read(map, FIRST_REG, data, BYTES);
		if (r->result)
			break;
		if ((i & 4095) == 4095)
			cond_resched();
	}
	r->elapsed_ns = ktime_get_ns() - start;
	r->cpu_end = raw_smp_processor_id();
	r->cycles = i;
	r->bus_reads = t->reads - reads;
	if (!r->result && (r->bus_reads != (u64)calls * TRANSFERS ||
			   memcmp(data, payload, BYTES)))
		r->result = -EIO;
	return r->result;
}

static int run_batches(bool raw)
{
	struct transport t = { .value_bytes = 1 };
	struct regmap *map = open_map(&t, false);
	unsigned int i;
	int ret = 0;

	if (IS_ERR(map))
		return PTR_ERR(map);
	for (i = 0; i < warmups + samples && !ret; i++) {
		struct batch *r = &rows[row_count++];

		r->warmup = i < warmups;
		r->sample = r->warmup ? i : i - warmups;
		ret = run_batch(map, &t, raw, r);
	}
	regmap_exit(map);
	return ret;
}

static int results_show(struct seq_file *s, void *unused)
{
	unsigned int i;

	seq_printf(s, "{\"schema\":1,\"mode\":\"%s\",\"calls\":%u,\"samples\":%u,\"warmups\":%u,\"checks\":[",
		   mode, calls, samples, warmups);
	for (i = 0; i < check_count; i++) {
		struct check *c = &checks[i];

		seq_printf(s, "%s{\"bits\":%u,\"fail_at\":%u,\"rc\":%d,\"transfers\":%u,\"wire\":\"%3phN\",\"lengths\":\"%3phN\",\"data\":\"%6phN\",\"converter\":\"%ps\",\"result\":%d}",
			   i ? "," : "", c->bits, c->fail_at, c->rc, c->transfers,
			   c->wire, c->lengths, c->data, c->converter, c->result);
	}
	seq_puts(s, "],\"rows\":[");
	for (i = 0; i < row_count; i++) {
		struct batch *r = &rows[i];

		seq_printf(s, "%s{\"sample\":%u,\"warmup\":%u,\"cycles\":%u,\"elapsed_ns\":%llu,\"bus_reads\":%llu,\"cpu_start\":%u,\"cpu_end\":%u,\"result\":%d}",
			   i ? "," : "", r->sample, r->warmup, r->cycles, r->elapsed_ns,
			   r->bus_reads, r->cpu_start, r->cpu_end, r->result);
	}
	seq_puts(s, "]}\n");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(results);

static int __init bulk_init(void)
{
	struct dentry *file;
	int ret;

	if (!calls || calls > 10000000 || !samples || samples > MAX_BATCHES ||
	    warmups > MAX_BATCHES - samples)
		return -EINVAL;
	if (!strcmp(mode, "check"))
		ret = run_checks();
	else if (!strcmp(mode, "bench") || !strcmp(mode, "raw"))
		ret = run_batches(!strcmp(mode, "raw"));
	else
		return -EINVAL;
	if (ret) {
		/* Unsuccessful insertion frees the module. Keep completed batches,
		 * plus any partial final batch, available to the guest collector.
		 */
		unsigned int i;

		for (i = 0; i < row_count; i++) {
			const struct batch *r = &rows[i];

			pr_err("c02-bulk mode=%s warmup=%u sample=%u cycles=%u reads=%llu elapsed_ns=%llu cpu_start=%u cpu_end=%u rc=%d\n",
			       mode, r->warmup, r->sample, r->cycles, r->bus_reads,
			       r->elapsed_ns, r->cpu_start, r->cpu_end, r->result);
		}
		return ret;
	}
	dir = debugfs_create_dir("kconc-c02-bulk", NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);
	file = debugfs_create_file("results", 0400, dir, NULL, &results_fops);
	if (IS_ERR(file)) {
		debugfs_remove_recursive(dir);
		return PTR_ERR(file);
	}
	return 0;
}

static void __exit bulk_exit(void)
{
	debugfs_remove_recursive(dir);
}
module_init(bulk_init);
module_exit(bulk_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Six-byte regmap XYZ component benchmark on a controlled bus");
