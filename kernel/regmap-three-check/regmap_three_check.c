// SPDX-License-Identifier: GPL-2.0-only
/* Three fixed callers and one resettable RAM register, private to this module. */
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/regmap.h>
#include <linux/wait.h>

#if (defined(TRI_NORMAL_BUILD) + defined(TRI_FAULT_BUILD) + defined(TRI_FIXED_BUILD)) != 1
#error Select exactly one build of the fixture
#endif

enum build_kind { NORMAL, FAULT, FIXED };
#ifdef TRI_NORMAL_BUILD
#define BUILD_NAME "normal"
static const enum build_kind build = NORMAL;
#elif defined(TRI_FAULT_BUILD)
#define BUILD_NAME "fault"
static const enum build_kind build = FAULT;
#else
#define BUILD_NAME "fixed"
static const enum build_kind build = FIXED;
#endif
MODULE_INFO(tri_variant, BUILD_NAME);

static char property[16] = "update";
static char variant[16] = BUILD_NAME;
static char order[16] = "ABC";
module_param_string(property, property, sizeof(property), 0444);
module_param_string(variant, variant, sizeof(variant), 0444);
module_param_string(order, order, sizeof(order), 0444);

#define NUM_ROLES 3
struct reader {
	struct task_struct *task;
	struct mutex local_lock;
	struct completion begin, halfway, resume, done;
	unsigned int index;
	int rc;
};

static struct reader readers[NUM_ROLES];
static DEFINE_MUTEX(shared_guard);
static DECLARE_WAIT_QUEUE_HEAD(stop_queue);
static struct regmap *map;
static unsigned int ram;
static atomic_t sequence = ATOMIC_INIT(0);
static bool mutex_case, cancelling;

static void event(struct reader *r, const char *kind, unsigned int value)
{
	pr_info("TRI_EVENT seq=%u role=%c tid=%d kind=%s reg=0 value=%u\n",
		(unsigned int)atomic_inc_return(&sequence), 'A' + r->index,
		task_pid_nr(current), kind, value);
}

static struct reader *current_reader(void)
{
	unsigned int i;

	for (i = 0; i < NUM_ROLES; i++)
		if (READ_ONCE(readers[i].task) == current)
			return &readers[i];
	return NULL;
}

static int tri_ram_read(void *ctx, unsigned int reg, unsigned int *value)
{
	struct reader *r = current_reader();

	if (reg != 0)
		return -EINVAL;
	*value = *(unsigned int *)ctx;
	if (r)
		event(r, "READ", *value);
	return 0;
}

static int tri_ram_write(void *ctx, unsigned int reg, unsigned int value)
{
	struct reader *r = current_reader();

	if (reg != 0)
		return -EINVAL;
	*(unsigned int *)ctx = value;
	if (r)
		event(r, "WRITE", value);
	return 0;
}

static const struct regmap_config config = {
	.name = "tri_regmap_ram",
	.reg_bits = 32,
	.val_bits = 32,
	.reg_read = tri_ram_read,
	.reg_write = tri_ram_write,
	.cache_type = REGCACHE_NONE,
};

static int next_half(struct reader *r)
{
	complete(&r->halfway);
	wait_for_completion(&r->resume);
	return READ_ONCE(cancelling) ? -ECANCELED : 0;
}

static int perform_update(struct reader *r)
{
	unsigned int bit = BIT(r->index), old;
	int rc;

	if (mutex_case) {
		/* Fault callers each own a different mutex for the same resource. */
		if (build == FAULT) {
			rc = next_half(r);
			if (rc)
				return rc;
		}
		return regmap_update_bits(map, 0, bit, bit);
	}
	if (build == NORMAL)
		return regmap_update_bits(map, 0, bit, bit);
	rc = regmap_read(map, 0, &old);
	if (!rc && build == FAULT)
		rc = next_half(r);
	if (rc)
		return rc;
	return regmap_write(map, 0, old | bit);
}

static int worker(void *arg)
{
	struct reader *r = arg;
	struct mutex *guard = NULL;

	wait_for_completion(&r->begin);
	if (READ_ONCE(cancelling)) {
		r->rc = -ECANCELED;
		goto done;
	}
	if (mutex_case)
		guard = build == FAULT ? &r->local_lock : &shared_guard;
	else if (build == FIXED)
		guard = &shared_guard;
	if (build == FIXED && r->index != 0) {
		/* The owner is waiting for this failed attempt, not for acquisition. */
		if (mutex_trylock(&shared_guard)) {
			mutex_unlock(&shared_guard);
			r->rc = -EUCLEAN;
			complete(&r->halfway);
			goto done;
		}
		pr_info("FIXTURE_CONTENDED role=%c tid=%d\n",
			'A' + r->index, task_pid_nr(current));
		r->rc = next_half(r);
		if (r->rc)
			goto done;
	}
	if (guard)
		mutex_lock(guard);
	event(r, "ENTER", 0);
	if (build == FIXED && r->index == 0) {
		pr_info("FIXTURE_HELD role=A tid=%d\n", task_pid_nr(current));
		r->rc = next_half(r);
	}
	if (!r->rc)
		r->rc = perform_update(r);
	event(r, "EXIT", 0);
	if (guard)
		mutex_unlock(guard);
	if (build == FIXED && r->index == 0)
		pr_info("FIXTURE_UNLOCKED role=A tid=%d\n", task_pid_nr(current));
done:
	pr_info("TRI_THREAD role=%c tid=%d rc=%d\n", 'A' + r->index,
		task_pid_nr(current), r->rc);
	complete(&r->done);
	/* Keep current valid until the coordinator joins all three readers. */
	wait_event(stop_queue, kthread_should_stop());
	return 0;
}

static int await(struct completion *c)
{
	return wait_for_completion_timeout(c, 5 * HZ) ? 0 : -ETIMEDOUT;
}

static int exercise(void)
{
	unsigned int i;
	struct reader *r;
	int rc;

	for (i = 0; i < NUM_ROLES; i++) {
		r = &readers[order[i] - 'A'];
		complete(&r->begin);
		rc = await(build == NORMAL ? &r->done : &r->halfway);
		if (rc || r->rc)
			return rc ? rc : r->rc;
	}
	if (build != NORMAL) {
		for (i = 0; i < NUM_ROLES; i++) {
			r = &readers[order[i] - 'A'];
			complete(&r->resume);
			rc = await(&r->done);
			if (rc || r->rc)
				return rc ? rc : r->rc;
		}
	}
	return 0;
}

static int __init tri_init(void)
{
	unsigned int started = 0, i, final = 0, initial = 0;
	int rc, read_rc;

	if (strcmp(variant, BUILD_NAME) ||
	    (strcmp(order, "ABC") && strcmp(order, "ACB")) ||
	    (strcmp(property, "update") && strcmp(property, "mutex")))
		return -EINVAL;
	mutex_case = !strcmp(property, "mutex");
	map = regmap_init(NULL, NULL, &ram, &config);
	if (IS_ERR(map))
		return PTR_ERR(map);
	rc = regmap_read(map, 0, &initial);
	if (rc || initial) {
		regmap_exit(map);
		return rc ? rc : -EUCLEAN;
	}
	pr_info("TRI_BEGIN property=%s variant=%s order=%s initial=%u\n",
		property, variant, order, initial);
	for (i = 0; i < NUM_ROLES; i++) {
		struct reader *r = &readers[i];

		r->index = i;
		mutex_init(&r->local_lock);
		init_completion(&r->begin);
		init_completion(&r->halfway);
		init_completion(&r->resume);
		init_completion(&r->done);
		r->task = kthread_create(worker, r, "tri_regmap/%c", 'A' + i);
		if (IS_ERR(r->task)) {
			rc = PTR_ERR(r->task);
			r->task = NULL;
			break;
		}
		wake_up_process(r->task);
		started++;
	}
	if (!rc)
		rc = exercise();
	/* Release every incomplete caller before joining a task on an error. */
	if (rc) {
		WRITE_ONCE(cancelling, true);
		for (i = 0; i < started; i++) {
			complete_all(&readers[i].begin);
			complete_all(&readers[i].resume);
		}
	}
	for (i = 0; i < started; i++) {
		kthread_stop(readers[i].task);
		WRITE_ONCE(readers[i].task, NULL);
	}
	read_rc = regmap_read(map, 0, &final);
	pr_info("TRI_READBACK tid=%d reg=0 value=%u rc=%d\n",
		task_pid_nr(current), final, read_rc);
	if (!rc)
		rc = read_rc;
	regmap_exit(map);
	pr_info("TRI_END final=%u ok=%d\n", final, !rc);
	return rc;
}

static void __exit tri_exit(void)
{
	pr_info("TRI_CLEAN\n");
}
module_init(tri_init);
module_exit(tri_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Three normal or intentionally separated updates of one private RAM register");
