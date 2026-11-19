// SPDX-License-Identifier: GPL-2.0
/* Measure real regcache restore operations on a privately owned RAM bus.
 * The owner resets the simulated device before each restore. Keeping that
 * reset outside other threads prevents an invalid concurrent power cycle.
 * RAM callbacks follow Linux regmap-ram.c (Arm Ltd, 2023); the benchmark,
 * repeatable reset epochs and result checks are project additions.
 */
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include "internal.h"

#define MAX_REGS 256
#define CASES 5
#define MAX_SAMPLES 8

static unsigned int samples = 3;
static unsigned int warmups = 2;
static bool quick;
static bool diagnostic;
static unsigned int case_id = CASES;
static unsigned int scale = 1;
module_param(samples, uint, 0);
module_param(warmups, uint, 0);
module_param(quick, bool, 0);
module_param(diagnostic, bool, 0);
module_param(case_id, uint, 0);
module_param(scale, uint, 0);

struct bench_case {
	const char *name;
	unsigned int regs, default_step, cycles, rw_per_cycle;
	bool restore;
};
static const struct bench_case cases[CASES] = {
	{ "restore32", 32, 1, 4096, 0, true },
	{ "restore256", 256, 1, 1024, 0, true },
	{ "sparse256", 256, 2, 1024, 0, true },
	{ "mixed256", 256, 1, 64, 1000, true },
	{ "steady256", 256, 1, 65536, 1, false },
};

struct bench_map {
	struct regmap *map;
	struct reg_default defaults[MAX_REGS];
	u32 ram[MAX_REGS], reset[MAX_REGS], desired[MAX_REGS];
	u64 bus_reads, bus_writes;
	unsigned int regs, default_count, restore_writes;
	struct reg_default *copied_defaults;
};
struct bench_result {
	unsigned int case_id, sample, cycles, cpu_start, cpu_end;
	bool warmup;
	u64 elapsed_ns, sync_ns, bus_reads, bus_writes, expected_writes;
	int result;
};
static struct bench_result results[CASES * (MAX_SAMPLES + 8)];
static unsigned int result_count;
static struct dentry *bench_dir;

static int ram_write(void *context, unsigned int reg, unsigned int value)
{
	struct bench_map *m = context;
	if (reg >= m->regs)
		return -EINVAL;
	m->ram[reg] = value;
	m->bus_writes++;
	return 0;
}

static int ram_read(void *context, unsigned int reg, unsigned int *value)
{
	struct bench_map *m = context;
	if (reg >= m->regs)
		return -EINVAL;
	*value = m->ram[reg];
	m->bus_reads++;
	return 0;
}

static const struct regmap_bus ram_bus = {
	.fast_io = false, .reg_write = ram_write, .reg_read = ram_read,
};

static int prepare(struct bench_map *m, const struct bench_case *c)
{
	struct regmap_config config = {
		.name = "c02-owned-map", .reg_bits = 32, .val_bits = 32,
		.reg_stride = 1, .fast_io = false, .cache_type = REGCACHE_FLAT,
	};
	unsigned int i;
	int ret = 0;

	m->regs = c->regs;
	for (i = 0; i < m->regs; i++) {
		m->reset[i] = i * 17U + 3U;
		m->ram[i] = m->reset[i];
		m->desired[i] = m->reset[i] ^ ((i % 4 >= 2) ? 1U : 0U);
		if (i % c->default_step == 0) {
			m->defaults[m->default_count].reg = i;
			m->defaults[m->default_count++].def = m->reset[i];
		}
		if (i % c->default_step || m->desired[i] != m->reset[i])
			m->restore_writes++;
	}
	config.max_register = m->regs - 1;
	config.reg_defaults = m->defaults;
	config.num_reg_defaults = m->default_count;
	m->map = regmap_init(NULL, &ram_bus, m, &config);
	if (IS_ERR(m->map)) {
		ret = PTR_ERR(m->map);
		m->map = NULL;
		return ret;
	}
	if (!m->map->can_sleep || m->map->lock_arg != m->map ||
	    m->map->cache_type != REGCACHE_FLAT || !m->map->cache_ops ||
	    m->map->cache_ops->sync || !m->map->reg_defaults ||
	    m->map->reg_defaults == m->defaults ||
	    m->map->num_reg_defaults != m->default_count)
		return -EINVAL;
	m->copied_defaults = m->map->reg_defaults;
	regcache_cache_only(m->map, true);
	for (i = 0; i < m->regs; i++) {
		ret = regmap_write(m->map, i, m->desired[i]);
		if (ret)
			break;
	}
	regcache_cache_only(m->map, false);
	if (ret)
		return ret;
	regcache_mark_dirty(m->map);
	return regcache_sync(m->map);
}

static int batch(struct bench_map *m, const struct bench_case *c,
		 struct bench_result *r)
{
	unsigned int cycle, j, reg, value;
	u64 start, end, inner = 0, old_writes = m->bus_writes;
	u64 old_reads = m->bus_reads;
	int ret = 0;

	r->cycles = quick ? 4 : c->cycles * scale;
	r->expected_writes = (u64)r->cycles *
		(c->rw_per_cycle + (c->restore ? m->restore_writes : 0));
	r->cpu_start = raw_smp_processor_id();
	start = ktime_get_ns();
	for (cycle = 0; cycle < r->cycles; cycle++) {
		for (j = 0; j < c->rw_per_cycle; j++) {
			reg = (cycle + j) % m->regs;
			ret = regmap_write(m->map, reg, m->desired[reg]);
			if (ret)
				goto finish;
			ret = regmap_read(m->map, reg, &value);
			if (ret || value != m->desired[reg]) {
				ret = ret ?: -EIO;
				goto finish;
			}
		}
		if (c->restore) {
			/* No other actor owns this map or simulated device. */
			for (reg = 0; reg < m->regs; reg++)
				m->ram[reg] = m->reset[reg];
			regcache_mark_dirty(m->map);
			if (diagnostic)
				inner = ktime_get_ns();
			ret = regcache_sync(m->map);
			if (diagnostic)
				r->sync_ns += ktime_get_ns() - inner;
			if (ret)
				goto finish;
		}
		if ((cycle & 63U) == 63U)
			cond_resched();
	}
finish:
	end = ktime_get_ns();
	r->cpu_end = raw_smp_processor_id();
	r->elapsed_ns = end - start;
	r->bus_writes = m->bus_writes - old_writes;
	r->bus_reads = m->bus_reads - old_reads;
	if (!ret && (r->bus_writes != r->expected_writes || r->bus_reads))
		ret = -EIO;
	if (!ret && (m->map->reg_defaults != m->copied_defaults ||
	    m->map->num_reg_defaults != m->default_count ||
	    memcmp(m->defaults, m->copied_defaults,
		   sizeof(*m->defaults) * m->default_count)))
		ret = -EIO;
	for (reg = 0; !ret && reg < m->regs; reg++)
		if (m->ram[reg] != m->desired[reg])
			ret = -EIO;
	r->result = ret;
	return ret;
}

static int results_show(struct seq_file *s, void *unused)
{
	unsigned int i;
	seq_printf(s, "{\"schema\":1,\"quick\":%u,\"diagnostic\":%u,\"samples\":%u,\"warmups\":%u,\"case_id\":%u,\"scale\":%u,\"rows\":[", quick, diagnostic, samples, warmups, case_id, scale);
	for (i = 0; i < result_count; i++) {
		struct bench_result *r = &results[i];
		seq_printf(s, "%s{\"case\":\"%s\",\"sample\":%u,\"warmup\":%u,\"cycles\":%u,\"elapsed_ns\":%llu,\"sync_ns\":%llu,\"bus_reads\":%llu,\"bus_writes\":%llu,\"expected_writes\":%llu,\"cpu_start\":%u,\"cpu_end\":%u,\"result\":%d}",
			i ? "," : "", cases[r->case_id].name, r->sample, r->warmup, r->cycles,
			r->elapsed_ns, r->sync_ns, r->bus_reads, r->bus_writes,
			r->expected_writes, r->cpu_start, r->cpu_end, r->result);
	}
	seq_puts(s, "]}\n");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(results);

/* Failed insertion discards module memory, so preserve every executed row in
 * the kernel log before returning the error to the loader. */
static int failed_run(int ret, unsigned int c, const char *stage)
{
	unsigned int i;
	pr_err("c02-failure {\"stage\":\"%s\",\"case_id\":%u,\"error\":%d,\"samples\":%u,\"warmups\":%u,\"quick\":%u,\"diagnostic\":%u,\"scale\":%u,\"rows\":%u}\n",
		stage, c, ret, samples, warmups, quick, diagnostic, scale, result_count);
	for (i = 0; i < result_count; i++) {
		struct bench_result *r = &results[i];
		pr_err("c02-failure-row {\"case\":\"%s\",\"sample\":%u,\"warmup\":%u,\"cycles\":%u,\"elapsed_ns\":%llu,\"sync_ns\":%llu,\"bus_reads\":%llu,\"bus_writes\":%llu,\"expected_writes\":%llu,\"cpu_start\":%u,\"cpu_end\":%u,\"result\":%d}\n",
			cases[r->case_id].name, r->sample, r->warmup, r->cycles,
			r->elapsed_ns, r->sync_ns, r->bus_reads, r->bus_writes,
			r->expected_writes, r->cpu_start, r->cpu_end, r->result);
	}
	return ret;
}

static int __init bench_init(void)
{
	unsigned int c, n;
	int ret = 0;
	if (!samples || samples > MAX_SAMPLES || warmups > 8 ||
	    case_id > CASES || !scale || scale > 64)
		return failed_run(-EINVAL, case_id, "parameters");
	for (c = 0; c < CASES; c++) {
		struct bench_map *m;
		if (case_id < CASES && c != case_id)
			continue;
		m = kzalloc(sizeof(*m), GFP_KERNEL);
		if (!m)
			return failed_run(-ENOMEM, c, "allocation");
		ret = prepare(m, &cases[c]);
		for (n = 0; !ret && n < warmups; n++) {
			struct bench_result *r = &results[result_count++];
			r->case_id = c;
			r->sample = n;
			r->warmup = true;
			ret = batch(m, &cases[c], r);
		}
		for (n = 0; !ret && n < samples; n++) {
			struct bench_result *r = &results[result_count++];
			r->case_id = c;
			r->sample = n;
			ret = batch(m, &cases[c], r);
		}
		if (m->map)
			regmap_exit(m->map);
		kfree(m);
		if (ret)
			return failed_run(ret, c, "prepare_or_batch");
	}
	bench_dir = debugfs_create_dir("kconc-c02", NULL);
	if (IS_ERR_OR_NULL(bench_dir))
		return failed_run(bench_dir ? PTR_ERR(bench_dir) : -ENOMEM, CASES, "result_directory");
	if (IS_ERR_OR_NULL(debugfs_create_file("results", 0400, bench_dir, NULL, &results_fops))) {
		debugfs_remove_recursive(bench_dir);
		return failed_run(-ENOMEM, CASES, "result_file");
	}
	pr_info("c02-bench completed rows=%u diagnostic=%u quick=%u\n", result_count, diagnostic, quick);
	return 0;
}

static void __exit bench_exit(void)
{
	debugfs_remove_recursive(bench_dir);
}
module_init(bench_init);
module_exit(bench_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Experimental regcache restore benchmark with owned RAM device");
