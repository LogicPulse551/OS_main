// SPDX-License-Identifier: GPL-2.0-only
/* Software I2C peripheral for direct reads through the native BMA400 driver. */
#include <linux/device.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>

#define SENSOR_ADDRESS 0x14
#define REGISTER_COUNT 128

static struct device *board;
static struct i2c_client *sensor;
static unsigned int sequence;
static u8 registers[REGISTER_COUNT];

/* Cold insertion starts in normal mode with constant signed 12-bit samples. */
static const u8 initial_registers[REGISTER_COUNT] = {
	[0x00] = 0x90, [0x03] = 0x04,
	[0x04] = 0x23, [0x05] = 0x01, /* X = 291 */
	[0x06] = 0x34, [0x07] = 0x02, /* Y = 564 */
	[0x19] = 0x02, [0x1a] = 0x06,
};

static int board_xfer(struct i2c_adapter *adapter, struct i2c_msg *msgs,
		      int count)
{
	unsigned int reg, size;
	int index;

	if (count != 1 && count != 2)
		return -EOPNOTSUPP;
	for (index = 0; index < count; index++) {
		if (msgs[index].addr != SENSOR_ADDRESS)
			return -ENXIO;
		if (msgs[index].flags & ~(I2C_M_RD | I2C_M_DMA_SAFE))
			return -EOPNOTSUPP;
		if (!msgs[index].len || !msgs[index].buf)
			return -EINVAL;
	}
	if (msgs[0].flags & I2C_M_RD)
		return -EOPNOTSUPP;
	reg = msgs[0].buf[0];
	if (reg >= sizeof(registers))
		return -EINVAL;
	if (count == 2) {
		if (msgs[0].len != 1 || !(msgs[1].flags & I2C_M_RD))
			return -EOPNOTSUPP;
		size = msgs[1].len;
		if (size > sizeof(registers) - reg)
			return -EINVAL;
		memcpy(msgs[1].buf, registers + reg, size);
		pr_info("BMA400_I2C_READ seq=%u tid=%d reg=0x%02x len=%u bytes=%*phN\n",
			++sequence, task_pid_nr(current), reg, size,
			(int)size, msgs[1].buf);
		return 2;
	}
	size = msgs[0].len - 1;
	if (!size || size > sizeof(registers) - reg)
		return -EINVAL;
	if (reg < 0x19)
		return -EACCES;
	memcpy(registers + reg, msgs[0].buf + 1, size);
	return 1;
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
	.name = "kconc BMA400 software I2C",
};

static int __init board_init(void)
{
	const struct i2c_board_info info = {
		I2C_BOARD_INFO("bma400", SENSOR_ADDRESS),
	};
	int ret;

	memcpy(registers, initial_registers, sizeof(registers));
	board = root_device_register("kconc-bma400-i2c");
	if (IS_ERR(board))
		return PTR_ERR(board);
	adapter.dev.parent = board;
	ret = i2c_add_adapter(&adapter);
	if (ret)
		goto release_board;
	sensor = i2c_new_client_device(&adapter, &info);
	if (!IS_ERR(sensor))
		return 0;
	ret = PTR_ERR(sensor);
	i2c_del_adapter(&adapter);
release_board:
	root_device_unregister(board);
	return ret;
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
MODULE_DESCRIPTION("In-memory I2C board for native BMA400 direct IIO axis reads");
