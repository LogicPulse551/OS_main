// SPDX-License-Identifier: GPL-2.0
/* Software SPI endpoint and data-ready interrupt for the unmodified KX022A. */
#include <linux/device.h>
#include <linux/fwnode.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/iio/iio.h>
#include <linux/iio/trigger.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>
#include <linux/workqueue.h>

#define DATA_BASE 0x06
#define FRAME_BYTES 6
#define MAX_CALLS 65536

static struct device *parent;
static struct spi_controller *controller;
static struct spi_device *sensor;
static struct fwnode_handle node;
static int sensor_irq;
static u8 registers[128];
/* The SPI core serializes messages; readers take snapshots at batch boundaries. */
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

bool kconc_kx022a_spi_controller(const struct spi_controller *candidate);
bool kconc_kx022a_spi_controller(const struct spi_controller *candidate)
{
	return candidate && candidate == READ_ONCE(controller) &&
	       READ_ONCE(candidate->transfer_one_message) == lab_transfer;
}
EXPORT_SYMBOL_GPL(kconc_kx022a_spi_controller);

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

enum run_mode { MODE_IRQ, MODE_READ, MODE_HANDLER };
static const char * const modes[] = { "irq", "read", "handler" };
static struct {
	enum run_mode mode;
	unsigned int calls, first, frames;
	u64 elapsed_ns, checksum;
	int error;
} batch;

static int match_iio(struct device *dev, const void *unused)
{
	return !strncmp(dev_name(dev), "iio:device", 10);
}

static void run_worker(struct work_struct *work)
{
	unsigned int i, j, before, calls = batch.calls;
	u64 start, check = 0;
	struct device *child;
	struct regmap *map;
	struct iio_dev *idev;
	u8 (*results)[FRAME_BYTES] = NULL;
	int err = 0;

	batch.error = -ENODEV;
	if (!sensor || !sensor->dev.driver ||
	    strcmp(sensor->dev.driver->name, "kx022a-spi"))
		return;
	child = device_find_child(&sensor->dev, NULL, match_iio);
	if (!child)
		return;
	idev = dev_to_iio_dev(child);
	map = dev_get_regmap(&sensor->dev, NULL);
	if (!map || !idev->trig)
		goto out;
	if (batch.mode == MODE_READ) {
		results = kvcalloc(calls, sizeof(*results), GFP_KERNEL);
		if (!results) {
			batch.error = -ENOMEM;
			goto out;
		}
	}
	before = READ_ONCE(sequence);
	start = ktime_get_ns();
	switch (batch.mode) {
	case MODE_READ:
		for (i = 0; i < calls; i++) {
			err = regmap_bulk_read(map, DATA_BASE, results[i], FRAME_BYTES);
			if (err)
				break;
		}
		break;
	case MODE_IRQ:
		for (i = 0; i < calls; i++) {
			err = generic_handle_irq_safe(sensor_irq);
			if (err)
				break;
			synchronize_irq(sensor_irq);
		}
		break;
	case MODE_HANDLER:
		for (i = 0; i < calls; i++)
			iio_trigger_poll_nested(idev->trig);
		break;
	}
	batch.elapsed_ns = ktime_get_ns() - start;
	batch.first = before + 1;
	batch.frames = READ_ONCE(sequence) - before;
	if (batch.frames != calls && !err)
		err = -EIO;
	if (results && !err) {
		for (i = 0; i < calls; i++) {
			u8 expected[FRAME_BYTES];

			frame_bytes(batch.first + i, expected);
			if (memcmp(results[i], expected, FRAME_BYTES)) {
				err = -EILSEQ;
				break;
			}
			for (j = 0; j < FRAME_BYTES; j++)
				check += results[i][j];
		}
	}
	batch.checksum = check;
	batch.error = err;
out:
	kvfree(results);
	put_device(child);
}
static DECLARE_WORK(run_work, run_worker);

static int set_run(const char *val, const struct kernel_param *kp)
{
	char mode[12];
	unsigned int count;
	int m;

	if (sscanf(val, "%11s %u", mode, &count) != 2 || !count || count > MAX_CALLS)
		return -EINVAL;
	m = match_string(modes, ARRAY_SIZE(modes), mode);
	if (m < 0)
		return m;
	memset(&batch, 0, sizeof(batch));
	batch.calls = count;
	batch.mode = m;
	schedule_work(&run_work);
	flush_work(&run_work);
	return batch.error;
}

static int get_run(char *buf, const struct kernel_param *kp)
{
	return sysfs_emit(buf, "mode=%s calls=%u frames=%u first=%u elapsed_ns=%llu checksum=%llu error=%d\n",
			  modes[batch.mode], batch.calls, batch.frames, batch.first,
			  batch.elapsed_ns, batch.checksum, batch.error);
}
static const struct kernel_param_ops run_ops = { .set = set_run, .get = get_run };
module_param_cb(run, &run_ops, NULL, 0600);

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
	return 0;
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
	if (attached)
		spi_unregister_device(sensor);
	else
		spi_dev_put(sensor);
	spi_unregister_controller(controller);
	irq_set_chip_and_handler(sensor_irq, NULL, NULL);
	irq_free_descs(sensor_irq, 1);
	root_device_unregister(parent);
}
module_init(lab_init);
module_exit(lab_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KX022A software SPI device and controlled read batches");
