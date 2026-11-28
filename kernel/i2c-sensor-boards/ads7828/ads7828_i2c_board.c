// SPDX-License-Identifier: GPL-2.0-only
/* Fixed-input ADC on a private software I2C adapter for native hwmon reads. */
#include <linux/device.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/sched.h>

#define ADC_ADDRESS 0x48
#define ADC_SAMPLE 1024

static struct device *board;
static struct i2c_client *sensor;
static unsigned int sequence;

/* Single-ended mode with the internal reference and converter enabled. */
static bool sample_command(unsigned int command)
{
	return command <= 0xff && (command & 0x8f) == 0x8c;
}

#ifdef HWMON_BOUNDED_REPLY
#include "replay_wait.h"
#endif

static int board_xfer(struct i2c_adapter *adapter, struct i2c_msg *msgs,
		      int count)
{
	unsigned int command;

	if (count != 2)
		return -EOPNOTSUPP;
	if (msgs[0].addr != ADC_ADDRESS || msgs[1].addr != ADC_ADDRESS)
		return -ENXIO;
	if ((msgs[0].flags & ~I2C_M_DMA_SAFE) ||
	    (msgs[1].flags & ~I2C_M_DMA_SAFE) != I2C_M_RD ||
	    msgs[0].len != 1 || msgs[1].len != 2 ||
	    !msgs[0].buf || !msgs[1].buf)
		return -EOPNOTSUPP;
	command = msgs[0].buf[0];
	if (!sample_command(command))
		return -EINVAL;
#ifdef HWMON_BOUNDED_REPLY
	defer_selected_reply(command, msgs[1].len);
#endif
	/* Equal voltages make operation identity depend on commands, not data. */
	msgs[1].buf[0] = ADC_SAMPLE >> 8;
	msgs[1].buf[1] = ADC_SAMPLE & 0xff;
	pr_info("ADS7828_I2C_READ seq=%u tid=%d reg=0x%02x len=2 bytes=%*phN\n",
		++sequence, task_pid_nr(current), command, 2, msgs[1].buf);
	return 2;
}

static u32 board_functionality(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C;
}

static const struct i2c_algorithm board_algorithm = {
	.xfer = board_xfer,
	.functionality = board_functionality,
};

static struct i2c_adapter adapter = {
	.owner = THIS_MODULE,
	.algo = &board_algorithm,
	.name = "kconc ADS7828 software I2C",
};

static int __init board_init(void)
{
	const struct i2c_board_info info = {
		I2C_BOARD_INFO("ads7828", ADC_ADDRESS),
	};
	int err;

	board = root_device_register("kconc-ads7828-i2c");
	if (IS_ERR(board))
		return PTR_ERR(board);
	adapter.dev.parent = board;
	err = i2c_add_adapter(&adapter);
	if (err)
		goto release_board;
	sensor = i2c_new_client_device(&adapter, &info);
	if (!IS_ERR(sensor))
		return 0;
	err = PTR_ERR(sensor);
	i2c_del_adapter(&adapter);
release_board:
	root_device_unregister(board);
	return err;
}

static void __exit board_exit(void)
{
	i2c_unregister_device(sensor);
	i2c_del_adapter(&adapter);
	root_device_unregister(board);
}

module_init(board_init);
module_exit(board_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Software I2C adapter for native ADS7828 hwmon voltage reads");
