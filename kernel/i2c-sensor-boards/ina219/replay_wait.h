/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BMA400_I2C_REPLAY_WAIT_H
#define BMA400_I2C_REPLAY_WAIT_H

#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/sysfs.h>

#define REPLAY_DELAY_MS 120
enum replay_phase { REPLAY_IDLE, REPLAY_ARMED, REPLAY_PENDING, REPLAY_DONE };
static const char *const phase_names[] = { "idle", "armed", "pending", "done" };
static DEFINE_MUTEX(replay_receipt_lock);
static enum replay_phase replay_phase;
static unsigned int replay_reg, replay_seq;
static pid_t replay_tid;
static u64 replay_start_ns, replay_end_ns;

static int arm_axis(const char *val, const struct kernel_param *param)
{
	unsigned int reg;
	int ret = kstrtouint(val, 0, &reg);

	if (ret)
		return ret;
	if (reg != REG_SHUNT && reg != REG_BUS)
		return -EINVAL;
	mutex_lock(&replay_receipt_lock);
	if (replay_phase == REPLAY_IDLE) {
		replay_reg = reg;
		replay_phase = REPLAY_ARMED;
	} else {
		ret = -EBUSY;
	}
	mutex_unlock(&replay_receipt_lock);
	return ret;
}

static int get_receipt(char *buf, const struct kernel_param *param)
{
	int size;

	mutex_lock(&replay_receipt_lock);
	size = sysfs_emit(buf, "phase=%s seq=%u reg=%u tid=%d start_ns=%llu end_ns=%llu delay_ms=%u\n",
			  phase_names[replay_phase], replay_seq, replay_reg, replay_tid,
			  replay_start_ns, replay_end_ns, REPLAY_DELAY_MS);
	mutex_unlock(&replay_receipt_lock);
	return size;
}

static const struct kernel_param_ops arm_ops = { .set = arm_axis };
static const struct kernel_param_ops receipt_ops = { .get = get_receipt };
module_param_cb(replay_arm, &arm_ops, NULL, 0200);
module_param_cb(replay_state, &receipt_ops, NULL, 0444);

static void defer_selected_reply(unsigned int reg, unsigned int size)
{
	mutex_lock(&replay_receipt_lock);
	if (replay_phase != REPLAY_ARMED || replay_reg != reg || size != 2) {
		mutex_unlock(&replay_receipt_lock);
		return;
	}
	replay_tid = task_pid_nr(current);
	replay_start_ns = ktime_get_ns();
	replay_seq++;
	replay_phase = REPLAY_PENDING;
	trace_printk("KCONC_I2C_CTRL phase=pending seq=%u reg=%u tid=%d\n",
		     replay_seq, replay_reg, replay_tid);
	mutex_unlock(&replay_receipt_lock);

	/* The adapter answers on its own timer even if nobody makes the peer read. */
	msleep(REPLAY_DELAY_MS);

	mutex_lock(&replay_receipt_lock);
	replay_end_ns = ktime_get_ns();
	replay_phase = REPLAY_DONE;
	trace_printk("KCONC_I2C_CTRL phase=done seq=%u reg=%u tid=%d\n",
		     replay_seq, replay_reg, replay_tid);
	mutex_unlock(&replay_receipt_lock);
}
#endif
