// SPDX-License-Identifier: GPL-2.0-only
/* In-memory board for the original bma400 SPI/IIO driver. SPI reads discard byte zero. */
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/spi/spi.h>

static struct device *parent;
static struct spi_controller *controller;
static struct spi_device *sensor;
static int irq;
static u8 regs[128];
static unsigned int frames, xreads, yreads, zreads;
static bool fail_y;

module_param(frames, uint, 0444);
module_param(xreads, uint, 0444);
module_param(yreads, uint, 0444);
module_param(zreads, uint, 0444);
module_param(fail_y, bool, 0600);

static int board_transfer(struct spi_controller *ctlr, struct spi_message *msg)
{
	struct spi_transfer *t;
	bool got_address = false, read = false;
	unsigned int reg = 0;
	int ret = 0;

	list_for_each_entry(t, &msg->transfers, transfer_list) {
		const u8 *tx = t->tx_buf;
		u8 *rx = t->rx_buf;
		unsigned int i;

		if (got_address && read && rx) {
			if (t->len < 2 || t->len > 3 || reg + t->len - 1 > sizeof(regs)) {
				ret = -EINVAL;
				break;
			}
			/* Deliberately recognizable dummy prefix, as on the actual SPI bus. */
			rx[0] = 0xad;
			if (reg == 4 && t->len == 3) {
				xreads++;
				regs[4] = xreads;
				regs[5] = xreads >> 8;
			} else if (reg == 6 && t->len == 3) {
				yreads++;
				if (READ_ONCE(fail_y)) {
					ret = -EIO;
					break;
				}
			} else if (reg == 8 && t->len == 3) {
				zreads++;
				frames++;
			}
			for (i = 1; i < t->len; i++)
				rx[i] = regs[reg++];
		} else if (tx) {
			for (i = 0; i < t->len; i++) {
				if (!got_address) {
					got_address = true;
					read = !!(tx[i] & 0x80);
					reg = tx[i] & 0x7f;
				} else if (!read && reg < sizeof(regs)) {
					regs[reg++] = tx[i];
				} else {
					ret = -EINVAL;
					break;
				}
			}
		} else {
			ret = -EINVAL;
		}
		if (ret)
			break;
		msg->actual_length += t->len;
	}
	msg->status = ret;
	spi_finalize_current_message(ctlr);
	return 0;
}

bool kconc_bma400_spi_controller(const struct spi_controller *candidate);
bool kconc_bma400_spi_controller(const struct spi_controller *candidate)
{
	return candidate && candidate == READ_ONCE(controller) &&
	       READ_ONCE(candidate->transfer_one_message) == board_transfer;
}
EXPORT_SYMBOL_GPL(kconc_bma400_spi_controller);

static bool attached, attach_attempted;

static int attach_board(const char *value, const struct kernel_param *kp)
{
	bool requested;
	int ret;

	if (kstrtobool(value, &requested) || !requested)
		return -EINVAL;
	/* Attach after module init, when symbol_get() can pin this provider. */
	if (!sensor)
		return -EAGAIN;
	if (attach_attempted)
		return -EBUSY;
	attach_attempted = true;
	ret = spi_add_device(sensor);
	attached = !ret;
	return ret;
}
static const struct kernel_param_ops attach_ops = { .set = attach_board };
module_param_cb(attach, &attach_ops, NULL, 0200);

static void noop_irq(struct irq_data *d) {}
static int board_irq_type(struct irq_data *d, unsigned int type)
{
	return type == IRQ_TYPE_EDGE_RISING ? 0 : -EINVAL;
}
static const struct irq_chip board_chip = {
	.name = "bma400-board-int1",
	.irq_mask = noop_irq,
	.irq_unmask = noop_irq,
	.irq_set_type = board_irq_type,
	.flags = IRQCHIP_ONESHOT_SAFE,
};

static int pulse(const char *value, const struct kernel_param *kp)
{
	unsigned int i, count;
	int ret;

	if (kstrtouint(value, 10, &count) || !count || count > 64)
		return -EINVAL;
	if (!sensor || !sensor->dev.driver)
		return -ENXIO;
	for (i = 0; i < count; i++) {
		ret = generic_handle_irq_safe(irq);
		if (ret)
			return ret;
		synchronize_irq(irq);
	}
	return 0;
}
static const struct kernel_param_ops pulse_ops = { .set = pulse };
module_param_cb(pulse, &pulse_ops, NULL, 0200);

static int __init board_init(void)
{
	int ret;

	regs[0] = 0x90;
	regs[3] = 4;
	regs[0x0e] = 0x80;
	regs[0x19] = 2;
	regs[0x1a] = 0x06;
	regs[6] = 0x34;
	regs[7] = 0x12;
	regs[8] = 0x78;
	regs[9] = 0x56;
	parent = root_device_register("bma400-board");
	if (IS_ERR(parent))
		return PTR_ERR(parent);
	irq = irq_alloc_descs(-1, 1, 1, NUMA_NO_NODE);
	if (irq < 0) {
		ret = irq;
		goto parent_out;
	}
	irq_set_chip_and_handler(irq, &board_chip, handle_simple_irq);
	irq_clear_status_flags(irq, IRQ_NOREQUEST | IRQ_NOTHREAD);
	controller = spi_alloc_host(parent, 0);
	if (!controller) {
		ret = -ENOMEM;
		goto irq_out;
	}
	controller->bus_num = -1;
	controller->num_chipselect = 1;
	controller->bits_per_word_mask = SPI_BPW_MASK(8);
	controller->max_speed_hz = 10000000;
	controller->transfer_one_message = board_transfer;
	ret = spi_register_controller(controller);
	if (ret) {
		spi_controller_put(controller);
		goto irq_out;
	}
	sensor = spi_alloc_device(controller);
	if (!sensor) {
		ret = -ENOMEM;
		goto ctlr_out;
	}
	strscpy(sensor->modalias, "bma400", sizeof(sensor->modalias));
	sensor->irq = irq;
	sensor->max_speed_hz = controller->max_speed_hz;
	spi_set_chipselect(sensor, 0, 0);
	return 0;
ctlr_out:
	spi_unregister_controller(controller);
irq_out:
	irq_set_chip_and_handler(irq, NULL, NULL);
	irq_free_descs(irq, 1);
parent_out:
	root_device_unregister(parent);
	return ret;
}
static void __exit board_exit(void)
{
	if (attached)
		spi_unregister_device(sensor);
	else
		spi_dev_put(sensor);
	spi_unregister_controller(controller);
	irq_set_chip_and_handler(irq, NULL, NULL);
	irq_free_descs(irq, 1);
	root_device_unregister(parent);
}
module_init(board_init);
module_exit(board_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Software BMA400 SPI board for six-byte IIO read verification");
