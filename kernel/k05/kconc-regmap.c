// SPDX-License-Identifier: GPL-2.0-only
/*
 * K05 synchronous test entry for the real Linux regmap core and RAM test bus.
 * Base: Linux 2fc2e45b0cd75cd56f252a0872a6d039f46cc42b (MAccConc tree).
 * The unmodified regmap-ram.c is Copyright (c) 2023 Arm Ltd, GPL-2.0.
 * Team code below supplies lifecycle/ABI glue, not a replacement regmap.
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
#include <linux/uaccess.h>

#include "internal.h"
#include "kconc-regmap.h"

struct kconc_regmap_context {
	struct mutex guard;
	struct regmap *map;
	struct regmap_ram_data *ram;
	u32 state;
	u32 epoch;
	u32 active;
	u32 completed_mask;
	struct kconc_regmap_role roles[KCONC_REGMAP_ROLES];
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

static void kconc_destroy_map(struct kconc_regmap_context *ctx)
{
	if (ctx->map)
		regmap_exit(ctx->map);
	ctx->map = NULL;
	ctx->ram = NULL;
	memset(ctx->roles, 0, sizeof(ctx->roles));
	ctx->completed_mask = 0;
}

/*
 * This function is reached after regmap_read() released its spinlock and
 * restored IRQ state, and before regmap_write() acquires that lock again.
 * No lifecycle mutex is held. Each logical role owns a distinct slot.
 * Bind control to the checkpoint store below, not to a bus callback or lock.
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
	memset(ctx->roles, 0, sizeof(ctx->roles));
	ctx->completed_mask = 0;
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
	unsigned int before = 0;
	unsigned int after = 0;
	int ret;

	if (copy_from_user(&request, arg, sizeof(request)))
		return -EFAULT;
	if (request.abi != KCONC_REGMAP_ABI || request.reserved ||
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
	ctx->active++;
	mutex_unlock(&ctx->guard);

	/* Synchronous in the ioctl caller: no worker/kthread changes KCOV owner. */
	ret = regmap_read(ctx->map, request.reg, &before);
	role->before = before;
	if (!ret)
		ret = kconc_regmap_checkpoint(role, request.epoch);
	if (!ret) {
		after = (before & ~request.mask) | (request.value & request.mask);
		ret = regmap_write(ctx->map, request.reg, after);
	}
	role->after = after;

	mutex_lock(&ctx->guard);
	role->status = ret;
	role->completed = 1;
	ctx->completed_mask |= BIT(request.role);
	if (ret)
		ctx->state = KCONC_REGMAP_POISONED;
	request.before = role->before;
	request.after = role->after;
	request.pid = role->pid;
	request.checkpoint = role->checkpoint;
	request.preempt_count = role->preempt_count;
	request.irqs_disabled = role->irqs_disabled;
	request.status = ret;
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
	kconc_destroy_map(ctx);
	mutex_unlock(&ctx->guard);
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
	static_assert(sizeof(struct kconc_regmap_op) == 56);
	static_assert(sizeof(struct kconc_regmap_status) == 120);
	return misc_register(&kconc_device);
}
device_initcall(kconc_regmap_init);

MODULE_DESCRIPTION("Kconc synchronous regmap lifecycle test entry");
MODULE_LICENSE("GPL");
