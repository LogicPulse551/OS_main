// SPDX-License-Identifier: GPL-2.0-only
/* A single caller schedules persistent kernel workers on one private RAM map. */
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/wait.h>

static char route[5];
module_param_string(route, route, sizeof(route), 0444);
static bool wrong_grant;
module_param(wrong_grant, bool, 0444);

struct actor {
	struct task_struct *task;
	wait_queue_head_t queue;
	struct completion armed;
	struct completion finished;
	unsigned int role, step, visits;
	bool pending;
	int rc;
};

static struct actor actors[3];
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

static int actor_main(void *arg)
{
	struct actor *actor = arg;
	unsigned int mask = BIT(actor->role);
	char role = 'A' + actor->role;

	for (;;) {
		unsigned int before = 0, after = 0;
		int rc;

		pr_info("CENTRAL_WAIT role=%c tid=%d visits=%u\n",
			role, current->pid, actor->visits);
		complete(&actor->armed);
		wait_event(actor->queue, kthread_should_stop() ||
			   smp_load_acquire(&actor->pending));
		if (kthread_should_stop())
			return 0;

		actor->visits++;
		pr_info("CENTRAL_TAKE step=%u role=%c tid=%d visit=%u\n",
			actor->step, role, current->pid, actor->visits);
		rc = regmap_read(map, 0, &before);
		if (!rc)
			rc = regmap_update_bits(map, 0, mask, actor->visits == 1 ? mask : 0);
		if (!rc)
			rc = regmap_read(map, 0, &after);
		pr_info("CENTRAL_DONE step=%u role=%c tid=%d visit=%u before=%u after=%u rc=%d\n",
			actor->step, role, current->pid, actor->visits, before, after, rc);
		actor->rc = rc;
		WRITE_ONCE(actor->pending, false);
		complete(&actor->finished);
	}
}

static int __init regmap_central_init(void)
{
	unsigned int started = 0, workers, initial = 0, final = 0, step;
	struct actor *actor;
	int rc, read_rc;
	const char *issued;

	if (!strcmp(route, "ABA") && !wrong_grant)
		workers = 2;
	else if (!strcmp(route, "ABCA"))
		workers = 3;
	else
		return -EINVAL;
	/* Inject one real wrong decision; leave workers and their updates identical. */
	issued = wrong_grant ? "ABAC" : route;
	map = regmap_init(NULL, NULL, &ram_value, &config);
	if (IS_ERR(map))
		return PTR_ERR(map);
	rc = regmap_read(map, 0, &initial);
	if (rc)
		goto stop;
	pr_info("CENTRAL_BEGIN route=%s wrong=%u coord=%d workers=%u initial=%u\n",
		route, wrong_grant, current->pid, workers, initial);

	while (started < workers) {
		actor = &actors[started];
		actor->role = started;
		init_waitqueue_head(&actor->queue);
		init_completion(&actor->armed);
		init_completion(&actor->finished);
		actor->task = kthread_run(actor_main, actor, "regactor/%u", started);
		if (IS_ERR(actor->task)) {
			rc = PTR_ERR(actor->task);
			goto stop;
		}
		started++;
		pr_info("CENTRAL_ROLE role=%c tid=%d\n", 'A' + actor->role, actor->task->pid);
		if (!wait_for_completion_timeout(&actor->armed, 5 * HZ)) {
			rc = -ETIMEDOUT;
			goto stop;
		}
	}
	for (step = 0; route[step]; step++) {
		char actual = issued[step];

		actor = &actors[actual - 'A'];
		actor->step = step;
		pr_info("CENTRAL_GRANT step=%u issuer=%d planned=%c actual=%c target=%d\n",
			step, current->pid, route[step], actual, actor->task->pid);
		smp_store_release(&actor->pending, true);
		wake_up(&actor->queue);
		if (!wait_for_completion_timeout(&actor->finished, 5 * HZ)) {
			rc = -ETIMEDOUT;
			break;
		}
		rc = actor->rc;
		pr_info("CENTRAL_ACK step=%u coord=%d role=%c tid=%d rc=%d\n",
			step, current->pid, actual, actor->task->pid, rc);
		if (rc)
			break;
		/* Observe the completed worker returning to the permission wait loop. */
		if (!wait_for_completion_timeout(&actor->armed, 5 * HZ)) {
			rc = -ETIMEDOUT;
			break;
		}
	}
stop:
	while (started)
		kthread_stop(actors[--started].task);
	read_rc = regmap_read(map, 0, &final);
	if (!rc)
		rc = read_rc;
	pr_info("CENTRAL_END coord=%d final=%u rc=%d\n", current->pid, final, rc);
	regmap_exit(map);
	return rc;
}

static void __exit regmap_central_exit(void)
{
	pr_info("CENTRAL_CLEAN\n");
}

module_init(regmap_central_init);
module_exit(regmap_central_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Central grants for complete updates on a private RAM regmap");
