/* SPDX-License-Identifier: GPL-2.0-only */
/* Included after the fixture so timed calls use its original owner and entry. */
#include <linux/uaccess.h>

static bool c07;
module_param(c07, bool, 0);
static DEFINE_MUTEX(c07_lock);

static ssize_t c07_write(struct file *file, const char __user *buf,
			 size_t len, loff_t *pos)
{
	static char * const modes[] = { "check", "bench", "raw", "observe" };
	char input[16];
	int i, ret;

	if (!len || len >= sizeof(input) || !cpumask_equal(current->cpus_ptr, cpumask_of(2)))
		return -EINVAL;
	if (copy_from_user(input, buf, len))
		return -EFAULT;
	if (memchr(input, '\0', len))
		return -EINVAL;
	input[len] = '\0';
	if (input[len - 1] == '\n')
		input[len - 1] = '\0';
	for (i = 0; i < ARRAY_SIZE(modes); i++)
		if (!strcmp(input, modes[i]))
			break;
	if (i == ARRAY_SIZE(modes))
		return -EINVAL;

	mutex_lock(&c07_lock);
	mode = modes[i];
	memset(checks, 0, sizeof(checks));
	memset(rows, 0, sizeof(rows));
	check_count = 0;
	row_count = 0;
	ret = !strcmp(mode, "check") ? run_checks() : run_batches(!strcmp(mode, "raw"));
	mutex_unlock(&c07_lock);
	if (ret)
		return ret;
	return len;
}

static const struct file_operations c07_run_fops = {
	.open = simple_open,
	.write = c07_write,
};

static int c07_results_show(struct seq_file *s, void *unused)
{
	int ret;

	mutex_lock(&c07_lock);
	ret = results_show(s, unused);
	mutex_unlock(&c07_lock);
	return ret;
}
DEFINE_SHOW_ATTRIBUTE(c07_results);

static int __init c07_setup(void)
{
	struct dentry *root, *file;

	if (!c07)
		return 0;
	if (strcmp(mode, "off") || !calls || calls > 10000000 || !samples ||
	    samples > MAX_BATCHES || warmups > MAX_BATCHES - samples)
		return -EINVAL;
	root = debugfs_create_dir("kconc-bma400-perf", NULL);
	if (IS_ERR(root))
		return PTR_ERR(root);
	file = debugfs_create_file("results", 0400, root, NULL, &c07_results_fops);
	if (!IS_ERR(file))
		file = debugfs_create_file("run", 0200, root, NULL, &c07_run_fops);
	if (IS_ERR(file)) {
		debugfs_remove_recursive(root);
		return PTR_ERR(file);
	}
	return 0;
}
late_initcall(c07_setup);
