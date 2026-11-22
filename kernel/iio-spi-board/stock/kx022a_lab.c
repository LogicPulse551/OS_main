// SPDX-License-Identifier: GPL-2.0
/* Software SPI endpoint and data-ready interrupt for the unmodified KX022A. */
#include <linux/device.h>
#include <linux/fwnode.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/property.h>
#include <linux/spi/spi.h>

#define DATA_BASE 0x06
#define FRAME_BYTES 6

static struct device *parent;
static struct spi_controller *controller;
static struct spi_device *sensor;
static struct fwnode_handle node;
static int sensor_irq;
static u8 registers[128];
/* The SPI core serializes changes to the frame counter. */
static unsigned int sequence;

static void frame_bytes(unsigned int seq, u8 *out)
{
	out[0] = seq;
	out[1] = seq >> 8;
	out[2] = 0x34;
	out[3] = 0x12;
	out[4] = 0x78;
	out[5] = 0x56;
}

static int lab_transfer(struct spi_controller *ctlr, struct spi_message *msg)
{
	struct spi_transfer *t;
	bool address = true, read = false;
	unsigned int reg = 0, i;
	int ret = 0;

	list_for_each_entry(t, &msg->transfers, transfer_list) {
		const u8 *tx = t->tx_buf;
		u8 *rx = t->rx_buf;

		if (!address && read && rx && reg == DATA_BASE && t->len == FRAME_BYTES) {
			unsigned int next = READ_ONCE(sequence) + 1;

			frame_bytes(next, rx);
			WRITE_ONCE(sequence, next);
			reg += t->len;
		} else {
			for (i = 0; i < t->len; i++) {
				if (address && tx) {
					read = !!(tx[i] & 0x80);
					reg = tx[i] & 0x7f;
					address = false;
				} else if (!address && reg < sizeof(registers) && read && rx) {
					rx[i] = registers[reg++];
				} else if (!address && reg < sizeof(registers) && !read && tx) {
					/* The software-reset bit clears before the first poll. */
					registers[reg] = reg == 0x19 ? tx[i] & ~0x80 : tx[i];
					reg++;
				} else {
					ret = -EINVAL;
					break;
				}
			}
			if (ret)
				break;
		}
		msg->actual_length += t->len;
	}
	msg->status = ret;
	spi_finalize_current_message(ctlr);
	return 0;
}

/* Board firmware supplies a named data-ready line. Other properties are absent. */
static int lab_strings(const struct fwnode_handle *fwnode, const char *name,
		       const char **values, size_t count)
{
	if (strcmp(name, "interrupt-names"))
		return -EINVAL;
	if (values && count)
		values[0] = "INT1";
	return 1;
}

static int lab_irq_get(const struct fwnode_handle *fwnode, unsigned int index)
{
	return index == 0 ? sensor_irq : -EINVAL;
}

static const char *lab_node_name(const struct fwnode_handle *fwnode)
{
	return "kx022a";
}

static const struct fwnode_operations node_ops = {
	.property_read_string_array = lab_strings,
	.irq_get = lab_irq_get,
	.get_name = lab_node_name,
};

static void irq_noop(struct irq_data *d) {}
static const struct irq_chip lab_chip = {
	.name = "kx022a-software-int1",
	.irq_mask = irq_noop,
	.irq_unmask = irq_noop,
	.flags = IRQCHIP_ONESHOT_SAFE,
};

static int __init lab_init(void)
{
	int err;

	registers[0x0f] = 0xc8;
	parent = root_device_register("kx022a-lab");
	if (IS_ERR(parent))
		return PTR_ERR(parent);
	sensor_irq = irq_alloc_descs(-1, 1, 1, NUMA_NO_NODE);
	if (sensor_irq < 0) {
		err = sensor_irq;
		goto out_parent;
	}
	irq_set_chip_and_handler(sensor_irq, &lab_chip, handle_simple_irq);
	irq_clear_status_flags(sensor_irq, IRQ_NOREQUEST | IRQ_NOTHREAD);
	controller = spi_alloc_host(parent, 0);
	if (!controller) {
		err = -ENOMEM;
		goto out_irq;
	}
	controller->bus_num = -1;
	controller->num_chipselect = 1;
	controller->bits_per_word_mask = SPI_BPW_MASK(8);
	controller->max_speed_hz = 10000000;
	controller->transfer_one_message = lab_transfer;
	err = spi_register_controller(controller);
	if (err) {
		spi_controller_put(controller);
		goto out_irq;
	}
	sensor = spi_alloc_device(controller);
	if (!sensor) {
		err = -ENOMEM;
		goto out_ctlr;
	}
	strscpy(sensor->modalias, "kx022a", sizeof(sensor->modalias));
	sensor->irq = sensor_irq;
	sensor->max_speed_hz = controller->max_speed_hz;
	spi_set_chipselect(sensor, 0, 0);
	fwnode_init(&node, &node_ops);
	device_set_node(&sensor->dev, &node);
	err = spi_add_device(sensor);
	if (!err)
		return 0;
	spi_dev_put(sensor);
out_ctlr:
	spi_unregister_controller(controller);
out_irq:
	irq_set_chip_and_handler(sensor_irq, NULL, NULL);
	irq_free_descs(sensor_irq, 1);
out_parent:
	root_device_unregister(parent);
	return err;
}

static void __exit lab_exit(void)
{
	spi_unregister_device(sensor);
	spi_unregister_controller(controller);
	irq_set_chip_and_handler(sensor_irq, NULL, NULL);
	irq_free_descs(sensor_irq, 1);
	root_device_unregister(parent);
}
module_init(lab_init);
module_exit(lab_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KX022A software SPI peripheral for normal IIO reads");
