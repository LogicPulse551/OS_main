// SPDX-License-Identifier: GPL-2.0-only
/*
 * K07 synchronous test entry for the real Linux regmap core and RAM test bus.
 * Base: Linux 2fc2e45b0cd75cd56f252a0872a6d039f46cc42b (MAccConc tree).
 * The unmodified regmap-ram.c is Copyright (c) 2023 Arm Ltd, GPL-2.0.
 * Team code below supplies lifecycle/ABI glue, not a replacement regmap.
 * The nonblocking map-wide admission contract uses one shared mutex. PER_ROLE
 * deliberately chooses different gates for the same contract. Real regmap
 * updates retain their own correct locking; this is a caller lock-domain bug.
 * This test device does not model physical hardware, IRQ or DMA behavior.
 */
#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/irqflags.h>
#include <linux/limits.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/preempt.h>
#include <linux/regmap.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

#include "internal.h"
#include "kconc-regmap.h"

struct kconc_regmap_context {
	struct mutex guard;
	struct mutex shared_gate;
	struct mutex private_gate[KCONC_REGMAP_ROLES];
	spinlock_t observer;
	struct regmap *map;
	struct regmap_ram_data *ram;
	u32 state;
	u32 epoch;
	u32 active;
	u32 completed_mask;
	u32 event_count;
	u32 in_cs;
	u32 max_depth;
	u32 occupants;
	struct kconc_regmap_role roles[KCONC_REGMAP_ROLES];
	struct kconc_regmap_event events[KCONC_REGMAP_EVENTS];
};

static const struct regmap_config kconc_map_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 1,
	.max_register = KCONC_REGMAP_REGS - 1,
	.cache_type = REGCACHE_NONE,
};

/* Called with guard held and no active operation. */
static int kconc_create_map(struct kconc_regmap_context *ctx)
{
	struct regmap_ram_data *ram;
	struct regmap *map;

	ram = kzalloc(sizeof(*ram), GFP_KERNEL);
	if (!ram)
		return -ENOMEM;
	ram->vals = kcalloc(KCONC_REGMAP_REGS, sizeof(*ram->vals), GFP_KERNEL);
	if (!ram->vals) {
		kfree(ram);
		return -ENOMEM;
	}
	map = regmap_init_ram(NULL, &kconc_map_config, ram);
	if (IS_ERR(map)) {
		/* The RAM helper already frees read/written on its failure path. */
		kfree(ram->vals);
		kfree(ram);
		return PTR_ERR(map);
	}
	/* regmap_exit() now owns ram and all three of its arrays. */
	ctx->ram = ram;
	ctx->map = map;
	return 0;
}

/* guard held, no active operations. Never reinitialize a potentially held lock. */
static void kconc_clear_observations(struct kconc_regmap_context *ctx)
{
	memset(ctx->roles, 0, sizeof(ctx->roles));
	memset(ctx->events, 0, sizeof(ctx->events));
	ctx->completed_mask = 0;
	ctx->event_count = 0;
	ctx->in_cs = 0;
	ctx->max_depth = 0;
	ctx->occupants = 0;
}

static u32 kconc_gates_locked(struct kconc_regmap_context *ctx)
{
	return (mutex_is_locked(&ctx->shared_gate) ? BIT(0) : 0) |
	       (mutex_is_locked(&ctx->private_gate[0]) ? BIT(1) : 0) |
	       (mutex_is_locked(&ctx->private_gate[1]) ? BIT(2) : 0);
}

static void kconc_destroy_map(struct kconc_regmap_context *ctx)
{
	if (ctx->map)
		regmap_exit(ctx->map);
	ctx->map = NULL;
	ctx->ram = NULL;
	kconc_clear_observations(ctx);
}

/*
 * A sleeping mutex gate is held, but no observer, lifecycle or regmap lock.
 * The peer uses trylock, so forced handoff never waits for this gate to unlock.
 * Bind only this store; never pause inside the observer or regmap's spinlock.
 */
static noinline int kconc_regmap_checkpoint(struct kconc_regmap_role *role,
					   u32 epoch)
{
	role->pid = task_pid_nr(current);
	role->preempt_count = preempt_count();
	role->irqs_disabled = irqs_disabled();
	if (role->preempt_count || role->irqs_disabled)
		return -EPERM;
	WRITE_ONCE(role->checkpoint, epoch);
	return 0;
}

/*
 * Observation only: a short spinlock makes boundary order and depth coherent.
 * It does not protect the body or prevent entry when occupancy exceeds one.
 * The marker and real API always execute after this lock restores IRQ state.
 */
static int kconc_observe(struct kconc_regmap_context *ctx, u32 logical_role,
			 u32 kind)
{
	struct kconc_regmap_role *role = &ctx->roles[logical_role];
	struct kconc_regmap_event *event;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&ctx->observer, flags);
	if (ctx->event_count >= KCONC_REGMAP_EVENTS ||
	    ctx->in_cs != hweight32(ctx->occupants)) {
		ret = -EUCLEAN;
		goto out;
	}
	if (kind == KCONC_REGMAP_EVENT_ENTER) {
		if (ctx->occupants & BIT(logical_role)) {
			ret = -EUCLEAN;
			goto out;
		}
		ctx->occupants |= BIT(logical_role);
		ctx->in_cs++;
		ctx->max_depth = max(ctx->max_depth, ctx->in_cs);
	} else if (kind == KCONC_REGMAP_EVENT_EXIT) {
		if (!(ctx->occupants & BIT(logical_role))) {
			ret = -EUCLEAN;
			goto out;
		}
		ctx->occupants &= ~BIT(logical_role);
		ctx->in_cs--;
	} else if (kind != KCONC_REGMAP_EVENT_BUSY) {
		ret = -EINVAL;
		goto out;
	}
	event = &ctx->events[ctx->event_count++];
	event->seq = ctx->event_count;
	event->role = logical_role;
	event->kind = kind;
	event->depth = ctx->in_cs;
	if (kind == KCONC_REGMAP_EVENT_ENTER) {
		role->enter_seq = event->seq;
		role->enter_depth = event->depth;
	} else if (kind == KCONC_REGMAP_EVENT_EXIT) {
		role->exit_seq = event->seq;
		role->exit_depth = event->depth;
	} else {
		role->busy_seq = event->seq;
		role->busy_depth = event->depth;
	}
out:
	spin_unlock_irqrestore(&ctx->observer, flags);
	return ret;
}

static void kconc_poison_epoch(struct kconc_regmap_context *ctx, u32 epoch)
{
	mutex_lock(&ctx->guard);
	if (ctx->epoch == epoch)
		ctx->state = KCONC_REGMAP_POISONED;
	mutex_unlock(&ctx->guard);
}

static long kconc_reset(struct kconc_regmap_context *ctx, void __user *arg)
{
	struct kconc_regmap_reset request;
	unsigned int value;
	unsigned int i;
	int ret = 0;

	if (copy_from_user(&request, arg, sizeof(request)))
		return -EFAULT;
	if (request.abi != KCONC_REGMAP_ABI || request.reserved ||
	    request.flags & ~KCONC_REGMAP_RESET_FAIL)
		return -EINVAL;
	mutex_lock(&ctx->guard);
	if (ctx->active) {
		ret = -EBUSY;
		goto out;
	}
	if (ctx->in_cs || ctx->occupants || kconc_gates_locked(ctx)) {
		ctx->state = KCONC_REGMAP_POISONED;
		ret = -EUCLEAN;
		goto out;
	}
	if (ctx->state == KCONC_REGMAP_POISONED) {
		ret = -EUCLEAN;
		goto out;
	}
	if (ctx->epoch == U32_MAX) {
		ret = -EOVERFLOW;
		goto out;
	}
	/* A partially initialized/reset map is never made executable. */
	ctx->state = KCONC_REGMAP_POISONED;
	if (!ctx->map) {
		ret = kconc_create_map(ctx);
		if (ret)
			goto out;
	}
	for (i = 0; i < KCONC_REGMAP_REGS; i++) {
		ret = regmap_write(ctx->map, i, request.initial[i]);
		if (ret)
			goto out;
	}
	if (request.flags & KCONC_REGMAP_RESET_FAIL) {
		/* Actual corruption at the reset checkpoint, not a forged verdict. */
		ret = regmap_write(ctx->map, 0, request.initial[0] ^ 1U);
		if (ret)
			goto out;
	}
	for (i = 0; i < KCONC_REGMAP_REGS; i++) {
		ret = regmap_read(ctx->map, i, &value);
		if (ret)
			goto out;
		if (value != request.initial[i]) {
			ret = -EIO;
			goto out;
		}
	}
	memset(ctx->ram->read, 0, KCONC_REGMAP_REGS * sizeof(*ctx->ram->read));
	memset(ctx->ram->written, 0, KCONC_REGMAP_REGS * sizeof(*ctx->ram->written));
	kconc_clear_observations(ctx);
	ctx->epoch++;
	request.epoch = ctx->epoch;
	ctx->state = KCONC_REGMAP_READY;
out:
	mutex_unlock(&ctx->guard);
	if (ret)
		return ret;
	if (copy_to_user(arg, &request, sizeof(request))) {
		kconc_poison_epoch(ctx, request.epoch);
		return -EFAULT;
	}
	return 0;
}

static long kconc_operation(struct kconc_regmap_context *ctx, void __user *arg)
{
	struct kconc_regmap_op request;
	struct kconc_regmap_role *role;
	struct mutex *gate;
	bool entered = false;
	int ret;
	int exit_ret;

	if (copy_from_user(&request, arg, sizeof(request)))
		return -EFAULT;
	if (request.abi != KCONC_REGMAP_ABI || request.reserved ||
	    request.mode > KCONC_REGMAP_MODE_PER_ROLE ||
	    request.role >= KCONC_REGMAP_ROLES || request.reg >= KCONC_REGMAP_REGS)
		return -EINVAL;
	mutex_lock(&ctx->guard);
	if (ctx->state == KCONC_REGMAP_POISONED) {
		ret = -EUCLEAN;
		goto reject;
	}
	if (ctx->state != KCONC_REGMAP_READY || !ctx->map) {
		ret = -ENODEV;
		goto reject;
	}
	if (request.epoch != ctx->epoch) {
		ret = -ESTALE;
		goto reject;
	}
	role = &ctx->roles[request.role];
	if (role->started) {
		ret = -EALREADY;
		goto reject;
	}
	role->started = 1;
	role->status = -EINPROGRESS;
	role->reg = request.reg;
	role->mode = request.mode;
	role->gate_id = request.mode == KCONC_REGMAP_MODE_SHARED ? 0 : request.role + 1;
	role->pid = task_pid_nr(current);
	role->preempt_count = preempt_count();
	role->irqs_disabled = irqs_disabled();
	ctx->active++;
	mutex_unlock(&ctx->guard);

	/* Synchronous in the ioctl caller: no worker/kthread changes KCOV owner. */
	gate = request.mode == KCONC_REGMAP_MODE_SHARED ?
		&ctx->shared_gate : &ctx->private_gate[request.role];
	if (role->preempt_count || role->irqs_disabled) {
		ret = -EPERM;
		goto complete;
	}
	role->acquired = mutex_trylock(gate);
	if (!role->acquired) {
		ret = kconc_observe(ctx, request.role, KCONC_REGMAP_EVENT_BUSY);
		if (!ret) {
			role->outcome = KCONC_REGMAP_OUTCOME_BUSY;
			ret = -EBUSY;
		}
		goto complete;
	}
	ret = kconc_observe(ctx, request.role, KCONC_REGMAP_EVENT_ENTER);
	if (!ret) {
		entered = true;
		ret = kconc_regmap_checkpoint(role, request.epoch);
	}
	if (!ret) {
		role->api_calls++;
		ret = regmap_update_bits(ctx->map, request.reg,
				 request.mask, request.value);
	}
	if (entered) {
		exit_ret = kconc_observe(ctx, request.role, KCONC_REGMAP_EVENT_EXIT);
		if (exit_ret)
			ret = exit_ret;
	}
	/* The acquiring ioctl task always releases its own actual gate. */
	mutex_unlock(gate);
	role->released = 1;
complete:
	if (role->outcome != KCONC_REGMAP_OUTCOME_BUSY)
		role->outcome = ret ? KCONC_REGMAP_OUTCOME_ERROR : KCONC_REGMAP_OUTCOME_SUCCESS;

	mutex_lock(&ctx->guard);
	role->status = ret;
	role->completed = 1;
	ctx->completed_mask |= BIT(request.role);
	if (ret && role->outcome != KCONC_REGMAP_OUTCOME_BUSY)
		ctx->state = KCONC_REGMAP_POISONED;
	request.result = *role;
	ctx->active--;
	mutex_unlock(&ctx->guard);
	/* Copy only the local result: a later reset cannot race this snapshot. */
	if (copy_to_user(arg, &request, sizeof(request))) {
		kconc_poison_epoch(ctx, request.epoch);
		return -EFAULT;
	}
	return ret;
reject:
	mutex_unlock(&ctx->guard);
	return ret;
}

static long kconc_status(struct kconc_regmap_context *ctx, void __user *arg,
			 bool teardown)
{
	struct kconc_regmap_status request;
	bool poisoned;
	unsigned int i;
	int ret = 0;

	if (copy_from_user(&request, arg, sizeof(request)))
		return -EFAULT;
	if (request.abi != KCONC_REGMAP_ABI)
		return -EINVAL;
	memset(&request, 0, sizeof(request));
	request.abi = KCONC_REGMAP_ABI;
	mutex_lock(&ctx->guard);
	if (teardown) {
		if (ctx->active) {
			ret = -EBUSY;
			goto out;
		}
		if (ctx->in_cs || ctx->occupants || kconc_gates_locked(ctx)) {
			ctx->state = KCONC_REGMAP_POISONED;
			ret = -EUCLEAN;
			goto out;
		}
		poisoned = ctx->state == KCONC_REGMAP_POISONED;
		kconc_destroy_map(ctx);
		/* Destroying resources does not clear an unsuccessful-reset verdict. */
		ctx->state = poisoned ? KCONC_REGMAP_POISONED : KCONC_REGMAP_EMPTY;
	}
	request.epoch = ctx->epoch;
	request.state = ctx->state;
	request.active = ctx->active;
	request.completed_mask = ctx->completed_mask;
	if (!ctx->active) {
		if (ctx->map) {
			for (i = 0; i < KCONC_REGMAP_REGS; i++) {
				ret = regmap_read(ctx->map, i, &request.values[i]);
				if (ret) {
					ctx->state = KCONC_REGMAP_POISONED;
					goto out;
				}
			}
		}
		memcpy(request.roles, ctx->roles, sizeof(request.roles));
		memcpy(request.events, ctx->events, sizeof(request.events));
		request.event_count = ctx->event_count;
		request.in_cs = ctx->in_cs;
		request.max_depth = ctx->max_depth;
		request.gates_locked = kconc_gates_locked(ctx);
		request.snapshot_valid = 1;
	}
out:
	mutex_unlock(&ctx->guard);
	if (ret)
		return ret;
	return copy_to_user(arg, &request, sizeof(request)) ? -EFAULT : 0;
}

static long kconc_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	struct kconc_regmap_context *ctx = file->private_data;
	void __user *user = (void __user *)arg;

	switch (command) {
	case KCONC_REGMAP_RESET:
		return kconc_reset(ctx, user);
	case KCONC_REGMAP_OP:
		return kconc_operation(ctx, user);
	case KCONC_REGMAP_STATUS:
		return kconc_status(ctx, user, false);
	case KCONC_REGMAP_TEARDOWN:
		return kconc_status(ctx, user, true);
	default:
		return -ENOTTY;
	}
}

static int kconc_open(struct inode *inode, struct file *file)
{
	struct kconc_regmap_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	mutex_init(&ctx->guard);
	mutex_init(&ctx->shared_gate);
	mutex_init(&ctx->private_gate[0]);
	mutex_init(&ctx->private_gate[1]);
	spin_lock_init(&ctx->observer);
	ctx->state = KCONC_REGMAP_EMPTY;
	file->private_data = ctx;
	return nonseekable_open(inode, file);
}

static int kconc_release(struct inode *inode, struct file *file)
{
	struct kconc_regmap_context *ctx = file->private_data;

	/* VFS keeps the struct file alive for each in-flight synchronous ioctl. */
	mutex_lock(&ctx->guard);
	WARN_ON_ONCE(ctx->active);
	WARN_ON_ONCE(ctx->in_cs || ctx->occupants || kconc_gates_locked(ctx));
	kconc_destroy_map(ctx);
	mutex_unlock(&ctx->guard);
	mutex_destroy(&ctx->private_gate[1]);
	mutex_destroy(&ctx->private_gate[0]);
	mutex_destroy(&ctx->shared_gate);
	mutex_destroy(&ctx->guard);
	kfree(ctx);
	return 0;
}

static const struct file_operations kconc_fops = {
	.owner = THIS_MODULE,
	.open = kconc_open,
	.release = kconc_release,
	.unlocked_ioctl = kconc_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
};

static struct miscdevice kconc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "kconc-regmap",
	.fops = &kconc_fops,
	.mode = 0600,
};

static int __init kconc_regmap_init(void)
{
	static_assert(sizeof(struct kconc_regmap_reset) == 32);
	static_assert(sizeof(struct kconc_regmap_op) == 112);
	static_assert(sizeof(struct kconc_regmap_role) == 80);
	static_assert(sizeof(struct kconc_regmap_event) == 16);
	static_assert(sizeof(struct kconc_regmap_status) == 280);
	return misc_register(&kconc_device);
}
device_initcall(kconc_regmap_init);

MODULE_DESCRIPTION("Kconc synchronous regmap mutex-domain test entry");
MODULE_LICENSE("GPL");
