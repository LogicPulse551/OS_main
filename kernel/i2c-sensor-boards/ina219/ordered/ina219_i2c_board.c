// SPDX-License-Identifier: GPL-2.0-only
/* A private fixed-input INA219 for native hwmon voltage reads. */
#include <linux/device.h>
#include <linux/i2c.h>
#include <linux/module.h>

#define INA219_ADDR 0x40
#define REG_CONFIG 0
#define REG_SHUNT 1
#define REG_BUS 2
#define REG_CALIBRATION 5

static struct device *board;
static struct i2c_client *sensor;
/* 400 * 10 microvolts and 1 * 4 millivolts both decode to 4 mV. */
static u16 registers[6] = { [REG_CONFIG] = 0x399f, [REG_SHUNT] = 400,
                           [REG_BUS] = (1 << 3) | 2 };

static int board_xfer(struct i2c_adapter *adap, struct i2c_msg *msgs, int nr)
{
	struct i2c_msg *w = &msgs[0];
	unsigned int reg;

	if ((nr != 1 && nr != 2) || w->addr != INA219_ADDR ||
	    (w->flags & ~I2C_M_DMA_SAFE) || !w->buf || !w->len)
		return -EOPNOTSUPP;
	reg = w->buf[0];
	if (reg >= ARRAY_SIZE(registers))
		return -EINVAL;
	if (nr == 1) {
		if (w->len != 3 || (reg != REG_CONFIG && reg != REG_CALIBRATION))
			return -EOPNOTSUPP;
		registers[reg] = (w->buf[1] << 8) | w->buf[2];
		return 1;
	}
	if (w->len != 1 || msgs[1].addr != INA219_ADDR ||
	    (msgs[1].flags & ~I2C_M_DMA_SAFE) != I2C_M_RD ||
	    msgs[1].len != 2 || !msgs[1].buf)
		return -EOPNOTSUPP;
	msgs[1].buf[0] = registers[reg] >> 8;
	msgs[1].buf[1] = registers[reg];
	return 2;
}

static u32 board_functionality(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C;
}

static const struct i2c_algorithm algo = {
	.xfer = board_xfer, .functionality = board_functionality,
};

static struct i2c_adapter adapter = {
	.owner = THIS_MODULE, .algo = &algo, .name = "kconc INA219 private I2C",
};

static int __init board_init(void)
{
	struct i2c_board_info info = { I2C_BOARD_INFO("ina219", INA219_ADDR) };
	int err;

	board = root_device_register("kconc-ina219-i2c");
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
MODULE_DESCRIPTION("Private I2C register bank for native INA219 voltage measurements");
