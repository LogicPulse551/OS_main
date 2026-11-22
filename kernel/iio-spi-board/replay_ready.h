/* SPDX-License-Identifier: GPL-2.0 */
/* One cold-start interval on the private software SPI controller. */
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/spi/spi.h>

enum board_window { WINDOW_IDLE, WINDOW_ARMED, WINDOW_WARMING, WINDOW_READY };
static atomic_t board_window = ATOMIC_INIT(WINDOW_IDLE);
static int board_prepare_tid;

static int board_arm_window(const char *value, const struct kernel_param *unused)
{
	if (!sysfs_streq(value, "1"))
		return -EINVAL;
	if (atomic_cmpxchg(&board_window, WINDOW_IDLE, WINDOW_ARMED) != WINDOW_IDLE)
		return -EBUSY;
	return 0;
}

static int board_show_window(char *buf, const struct kernel_param *unused)
{
	return sysfs_emit(buf, "%d\n", atomic_read_acquire(&board_window));
}

static int board_show_prepare_tid(char *buf, const struct kernel_param *unused)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(board_prepare_tid));
}

static const struct kernel_param_ops board_arm_ops = { .set = board_arm_window };
static const struct kernel_param_ops board_window_ops = { .get = board_show_window };
static const struct kernel_param_ops board_prepare_tid_ops = { .get = board_show_prepare_tid };
module_param_cb(window_arm, &board_arm_ops, NULL, 0200);
module_param_cb(window_state, &board_window_ops, NULL, 0444);
module_param_cb(window_tid, &board_prepare_tid_ops, NULL, 0444);

static int board_prepare_once(struct spi_controller *controller)
{
	/* SPI serializes prepare calls for this controller with its io_mutex. */
	if (atomic_read_acquire(&board_window) == WINDOW_ARMED) {
		WRITE_ONCE(board_prepare_tid, current->pid);
		atomic_set_release(&board_window, WINDOW_WARMING);
		/* The board becomes ready even if the peer never starts its read. */
		msleep(120);
		atomic_set_release(&board_window, WINDOW_READY);
	}
	return 0;
}
