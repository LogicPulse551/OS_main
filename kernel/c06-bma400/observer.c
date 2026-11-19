// SPDX-License-Identifier: GPL-2.0-only
/* Built into the functional guest only. The fixture and its conversion code remain separate. */
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/dcache.h>
#include <linux/kallsyms.h>
#include <linux/kmod.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/stacktrace.h>
#include "internal.h"
#include "trace.h"

#define WAIT msecs_to_jiffies(10000)

struct map_report {
	unsigned int width, raw_starts, private_hits, public_hits, unresolved;
	unsigned int bulk_success, control_ready, overlap, control_ok, control_joined;
	unsigned int hidden, target_live_visible, control_live_visible;
	unsigned int target_removed, control_removed, control_bus_reads;
	int reader_rc;
};

static struct map_report rows[4];
static unsigned int nrows, errors;
static struct regmap *active, *comparison;
static struct task_struct *worker;
static struct completion ready, entered, target_read, done, release_control;
static DECLARE_WAIT_QUEUE_HEAD(stop_wait);
static DEFINE_MUTEX(results_lock);
static bool enabled;

static int present(const char *name)
{
	struct dentry *root = debugfs_lookup("regmap", NULL);
	struct dentry *entry;

	if (!root)
		return -ENOENT;
	entry = debugfs_lookup(name, root);
	dput(root);
	if (!entry)
		return 0;
	dput(entry);
	return 1;
}

static int control_read(void *ctx, unsigned int reg, unsigned int *val)
{
	struct map_report *row = ctx;

	/* Only the control owner's transaction participates in the rendezvous.
	 * The later live debugfs check reads the same ordinary map independently.
	 */
	if (current == READ_ONCE(worker)) {
		row->control_bus_reads++;
		complete(&entered);
		if (!wait_for_completion_timeout(&target_read, WAIT))
			return -ETIMEDOUT;
		row->overlap = 1;
	}
	*val = 0x5a + reg;
	return 0;
}

static int run_control(void *ctx)
{
	struct map_report *row = ctx;
	const struct regmap_config cfg = {
		.name = "c06-control", .reg_bits = 8, .val_bits = 8, .max_register = 1,
		.reg_read = control_read, .cache_type = REGCACHE_NONE,
	};
	struct regmap *map = regmap_init(NULL, NULL, ctx, &cfg);
	unsigned int value;
	int ret;

	if (!IS_ERR(map)) {
		comparison = map;
		row->control_ready = map != active;
	}
	complete(&ready);
	if (!IS_ERR(map)) {
		ret = regmap_read(map, 1, &value);
		row->control_ok = !ret && value == 0x5b;
		complete(&done);
		/* The target owner releases this map after the live filesystem check. */
		if (!wait_for_completion_timeout(&release_control, 3 * WAIT))
			row->control_ok = 0;
		regmap_exit(map);
		comparison = NULL;
	} else {
		complete(&entered);
		complete(&done);
	}
	/* kthread_stop joins a live task even when all work has already finished. */
	wait_event_interruptible(stop_wait, kthread_should_stop());
	return 0;
}

static void read_started(void *unused, struct regmap *map, unsigned int reg, int count)
{
	unsigned long stack[24];
	char symbol[KSYM_SYMBOL_LEN];
	struct map_report *row;
	unsigned int i, nr;

	if (map != READ_ONCE(active))
		return;
	row = &rows[nrows - 1];
	row->raw_starts++;
	if (row->raw_starts == 1)
		complete(&target_read);
	nr = stack_trace_save(stack, ARRAY_SIZE(stack), 0);
	for (i = 0; i < nr; i++) {
		sprint_symbol_no_offset(symbol, stack[i]);
		if (!strcmp(symbol, "kconc_bma400_bulk_read")) {
			row->private_hits++;
			return;
		}
		if (!strcmp(symbol, "regmap_bulk_read")) {
			row->public_hits++;
			return;
		}
	}
	row->unresolved++;
}

static void success(void *unused, struct regmap *map, unsigned int reg, const void *val, int len)
{
	if (map == READ_ONCE(active))
		rows[nrows - 1].bulk_success++;
}

static void removed(struct map_report *row)
{
	row->target_removed = present("dummy-c02-bulk") == 0;
	row->control_removed = present("dummy-c06-control") == 0;
}

void kconc_c06_map_open(struct regmap *map);
void kconc_c06_map_closing(struct regmap *map);

void kconc_c06_map_open(struct regmap *map)
{
	struct map_report *row;

	if (!enabled || !map->name || strcmp(map->name, "c02-bulk"))
		return;
	mutex_lock(&results_lock);
	if (active || nrows >= ARRAY_SIZE(rows)) {
		errors++;
		mutex_unlock(&results_lock);
		return;
	}
	if (nrows)
		removed(&rows[nrows - 1]);
	row = &rows[nrows++];
	row->width = map->format.val_bytes * 8;
	row->hidden = map->debugfs_disable;
	row->reader_rc = -ENODATA;
	init_completion(&ready);
	init_completion(&entered);
	init_completion(&target_read);
	init_completion(&done);
	init_completion(&release_control);
	WRITE_ONCE(active, map);
	worker = kthread_create(run_control, row, "c06-regmap-ctrl");
	if (IS_ERR(worker)) {
		worker = NULL;
		errors++;
	} else {
		wake_up_process(worker);
		if (!wait_for_completion_timeout(&ready, WAIT) ||
		    !wait_for_completion_timeout(&entered, WAIT) || !row->control_ready)
			errors++;
	}
	mutex_unlock(&results_lock);
}

void kconc_c06_map_closing(struct regmap *map)
{
	struct map_report *row;
	char *argv[] = { "/c06-read", NULL, NULL };
	char *envp[] = { NULL };

	if (map != READ_ONCE(active))
		return;
	mutex_lock(&results_lock);
	row = &rows[nrows - 1];
	if (worker) {
		if (!wait_for_completion_timeout(&done, WAIT))
			errors++;
		row->target_live_visible = present("dummy-c02-bulk") == 1;
		row->control_live_visible = present("dummy-c06-control") == 1;
		argv[1] = row->hidden ? "hidden" : "visible";
		row->reader_rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
		if (row->reader_rc || !row->control_live_visible ||
		    row->target_live_visible == row->hidden || comparison == map)
			errors++;
		complete(&release_control);
		row->control_joined = kthread_stop(worker) == 0;
		worker = NULL;
		if (!row->control_ok || !row->overlap || !row->control_joined ||
		    row->control_bus_reads != 1 || row->unresolved)
			errors++;
	}
	WRITE_ONCE(active, NULL);
	mutex_unlock(&results_lock);
}

static int observer_show(struct seq_file *s, void *unused)
{
	unsigned int i;

	mutex_lock(&results_lock);
	if (nrows && !active)
		removed(&rows[nrows - 1]);
	seq_printf(s, "{\"schema\":1,\"errors\":%u,\"maps\":[", errors);
	for (i = 0; i < nrows; i++) {
		struct map_report *r = &rows[i];

		seq_printf(s, "%s{\"width\":%u,\"hidden\":%u,\"raw_starts\":%u,\"private_hits\":%u,\"public_hits\":%u,\"unresolved\":%u,\"bulk_success\":%u,",
			   i ? "," : "", r->width,r->hidden,r->raw_starts,r->private_hits,r->public_hits,r->unresolved,r->bulk_success);
		seq_printf(s, "\"control_ready\":%u,\"overlap\":%u,\"control_ok\":%u,\"control_joined\":%u,\"control_bus_reads\":%u,",
			   r->control_ready,r->overlap,r->control_ok,r->control_joined,r->control_bus_reads);
		seq_printf(s, "\"target_live_visible\":%u,\"control_live_visible\":%u,\"target_removed\":%u,\"control_removed\":%u,\"reader_rc\":%d}",
			   r->target_live_visible,r->control_live_visible,r->target_removed,r->control_removed,r->reader_rc);
	}
	seq_puts(s, "]}\n");
	mutex_unlock(&results_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(observer);

static int __init setup_observer(void)
{
	struct dentry *dir;
	int ret = register_trace_regmap_hw_read_start(read_started, NULL);

	if (ret)
		return ret;
	ret = register_trace_regmap_bulk_read(success, NULL);
	if (ret) {
		unregister_trace_regmap_hw_read_start(read_started, NULL);
		return ret;
	}
	dir = debugfs_create_dir("kconc-c06-observer", NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);
	debugfs_create_file("results", 0400, dir, NULL, &observer_fops);
	enabled = true;
	return 0;
}
subsys_initcall(setup_observer);
