// SPDX-License-Identifier: GPL-2.0-only
/* Exercise complete regmap updates on a private, initially zero register. */
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/wait.h>

#define MAX_ACTORS 5
#define OPS_PER_ACTOR 2

static unsigned int threads;
module_param(threads, uint, 0444);
static char order[OPS_PER_ACTOR * MAX_ACTORS + 1];
module_param_string(order, order, sizeof(order), 0444);

struct actor {
	struct task_struct *task;
	wait_queue_head_t queue;
	struct completion finished;
	unsigned int role;
	unsigned int step;
	unsigned int calls;
	bool pending;
	int rc;
};

static struct actor actors[MAX_ACTORS];
static unsigned int ram_value;
static struct regmap *map;

static int ram_read(void *ctx, unsigned int reg, unsigned int *value)
{
	if (reg != 0)
		return -EINVAL;
	*value = *(unsigned int *)ctx;
	return 0;
}

static int ram_write(void *ctx, unsigned int reg, unsigned int value)
{
	if (reg != 0)
		return -EINVAL;
	*(unsigned int *)ctx = value;
	return 0;
}

static const struct regmap_config config = {
	.name = "regmap_actors",
	.reg_bits = 32,
	.val_bits = 32,
	.reg_read = ram_read,
	.reg_write = ram_write,
	.cache_type = REGCACHE_NONE,
};

static bool valid_order(void)
{
	unsigned int count[MAX_ACTORS] = {};
	unsigned int i, role;

	if (threads < 2 || threads > MAX_ACTORS ||
	    strlen(order) != OPS_PER_ACTOR * threads)
		return false;
	for (i = 0; order[i]; i++) {
		if (order[i] < '0' || order[i] >= '0' + threads)
			return false;
		role = order[i] - '0';
		if (++count[role] > OPS_PER_ACTOR)
			return false;
	}
	return true;
}

static int actor_main(void *arg)
{
	struct actor *actor = arg;
	unsigned int mask = BIT(actor->role);

	for (;;) {
		unsigned int before = 0, after = 0;
		int rc;

		wait_event(actor->queue, kthread_should_stop() ||
			   smp_load_acquire(&actor->pending));
		if (kthread_should_stop())
			return 0;

		rc = regmap_read(map, 0, &before);
		if (!rc)
			rc = regmap_update_bits(map, 0, mask, actor->calls ? 0 : mask);
		if (!rc)
			rc = regmap_read(map, 0, &after);
		pr_info("REGACT step=%u role=%u pid=%d before=%u after=%u rc=%d\n",
			actor->step, actor->role, current->pid, before, after, rc);
		actor->rc = rc;
		actor->calls++;
		WRITE_ONCE(actor->pending, false);
		complete(&actor->finished);
	}
}

static int __init regmap_actors_init(void)
{
	unsigned int started = 0, step, final = 0;
	struct actor *actor;
	int read_rc, rc = 0;

	if (!valid_order())
		return -EINVAL;
	map = regmap_init(NULL, NULL, &ram_value, &config);
	if (IS_ERR(map))
		return PTR_ERR(map);

	while (started < threads) {
		actor = &actors[started];
		actor->role = started;
		init_waitqueue_head(&actor->queue);
		init_completion(&actor->finished);
		actor->task = kthread_run(actor_main, actor, "regactor/%u", started);
		if (IS_ERR(actor->task)) {
			rc = PTR_ERR(actor->task);
			goto stop;
		}
		started++;
	}

	for (step = 0; order[step]; step++) {
		actor = &actors[order[step] - '0'];
		actor->step = step;
		smp_store_release(&actor->pending, true);
		wake_up(&actor->queue);
		if (!wait_for_completion_timeout(&actor->finished, 5 * HZ)) {
			rc = -ETIMEDOUT;
			pr_err("REGACT timeout step=%u role=%u\n", step, actor->role);
			break;
		}
		rc = actor->rc;
		if (rc)
			break;
	}

stop:
	/* Join before reading the final state, including after a timed-out step. */
	while (started)
		kthread_stop(actors[--started].task);
	read_rc = regmap_read(map, 0, &final);
	if (!rc)
		rc = read_rc;
	if (!rc && final != 0)
		rc = -EUCLEAN;
	pr_info("REGACT final=%u rc=%d\n", final, rc);
	regmap_exit(map);
	return rc;
}

static void __exit regmap_actors_exit(void)
{
	pr_info("REGACT clean\n");
}

module_init(regmap_actors_init);
module_exit(regmap_actors_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Ordered bit updates on a private RAM regmap by independent kernel threads");
