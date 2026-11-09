#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched/signal.h>
#include <linux/sysinfo.h>
#include <linux/uaccess.h>

#define DRIVER_NAME "sysmetrics"
#define DEVICE_NAME "sysmetrics"
#define CLASS_NAME  "sysmetrics_class"
#define SNAPSHOT_SIZE (64 * 1024)

struct sysmetrics_device {
	dev_t devt;
	struct cdev cdev;
	struct class *class;
	struct device *device;
	char *snapshot;
	size_t snapshot_len;
	struct mutex lock;
};

static struct sysmetrics_device sysdev;

static void build_snapshot(struct sysmetrics_device *dev)
{
	struct sysinfo info;
	struct task_struct *task;
	unsigned long total_ram, free_ram, used_ram;
	size_t pos = 0;
	int process_count = 0, listed = 0;

	si_meminfo(&info);
	total_ram = (unsigned long)info.totalram * info.mem_unit;
	free_ram = (unsigned long)info.freeram * info.mem_unit;
	used_ram = total_ram - free_ram;
	pos += scnprintf(dev->snapshot + pos, SNAPSHOT_SIZE - pos,
		"SYS_METRICS_V1\n"
		"cpu_online=%u\n"
		"cpu_possible=%u\n"
		"ram_total_bytes=%lu\n"
		"ram_free_bytes=%lu\n"
		"ram_used_bytes=%lu\n"
		"processes:\n",
		num_online_cpus(), num_possible_cpus(), total_ram, free_ram, used_ram);

	rcu_read_lock();
	for_each_process(task) {
		process_count++;
		if (listed >= 512 || pos >= SNAPSHOT_SIZE - 96)
			continue;
		pos += scnprintf(dev->snapshot + pos, SNAPSHOT_SIZE - pos,
			"pid=%d comm=%s state=%c\n", task_pid_nr(task), task->comm,
			task_state_to_char(task));
		listed++;
	}
	rcu_read_unlock();
	if (listed < process_count && pos < SNAPSHOT_SIZE - 64)
		pos += scnprintf(dev->snapshot + pos, SNAPSHOT_SIZE - pos,
			"process_list_truncated=yes\n");
	pos += scnprintf(dev->snapshot + pos, SNAPSHOT_SIZE - pos,
		"process_count=%d\n", process_count);
	dev->snapshot_len = pos;
}

static int sysmetrics_open(struct inode *inode, struct file *file)
{
	file->private_data = container_of(inode->i_cdev,
					  struct sysmetrics_device, cdev);
	return 0;
}

static ssize_t sysmetrics_read(struct file *file, char __user *buf,
				       size_t count, loff_t *ppos)
{
	struct sysmetrics_device *dev = file->private_data;
	size_t to_copy;

	if (!dev)
		return -EINVAL;
	mutex_lock(&dev->lock);
	if (*ppos == 0)
		build_snapshot(dev);
	if (*ppos >= dev->snapshot_len) {
		mutex_unlock(&dev->lock);
		return 0;
	}
	to_copy = min(count, dev->snapshot_len - (size_t)*ppos);
	if (copy_to_user(buf, dev->snapshot + *ppos, to_copy)) {
		mutex_unlock(&dev->lock);
		return -EFAULT;
	}
	*ppos += to_copy;
	mutex_unlock(&dev->lock);
	return to_copy;
}

static ssize_t sysmetrics_write(struct file *file, const char __user *buf,
					size_t count, loff_t *ppos)
{
	return -EOPNOTSUPP;
}

static const struct file_operations sysmetrics_fops = {
	.owner = THIS_MODULE,
	.open = sysmetrics_open,
	.read = sysmetrics_read,
	.write = sysmetrics_write,
	.llseek = noop_llseek,
};

static int __init sysmetrics_init(void)
{
	int ret;

	memset(&sysdev, 0, sizeof(sysdev));
	mutex_init(&sysdev.lock);
	sysdev.snapshot = kzalloc(SNAPSHOT_SIZE, GFP_KERNEL);
	if (!sysdev.snapshot)
		return -ENOMEM;
	ret = alloc_chrdev_region(&sysdev.devt, 0, 1, DRIVER_NAME);
	if (ret)
		goto err_free_snapshot;
	cdev_init(&sysdev.cdev, &sysmetrics_fops);
	ret = cdev_add(&sysdev.cdev, sysdev.devt, 1);
	if (ret)
		goto err_unregister;
	sysdev.class = class_create(CLASS_NAME);
	if (IS_ERR(sysdev.class)) {
		ret = PTR_ERR(sysdev.class);
		goto err_cdev;
	}
	sysdev.device = device_create(sysdev.class, NULL, sysdev.devt, NULL,
				      DEVICE_NAME);
	if (IS_ERR(sysdev.device)) {
		ret = PTR_ERR(sysdev.device);
		goto err_class;
	}
	pr_info(DRIVER_NAME ": loaded: /dev/" DEVICE_NAME " (major=%d minor=%d)\n",
		MAJOR(sysdev.devt), MINOR(sysdev.devt));
	return 0;
err_class:
	class_destroy(sysdev.class);
err_cdev:
	cdev_del(&sysdev.cdev);
err_unregister:
	unregister_chrdev_region(sysdev.devt, 1);
err_free_snapshot:
	kfree(sysdev.snapshot);
	return ret;
}

static void __exit sysmetrics_exit(void)
{
	device_destroy(sysdev.class, sysdev.devt);
	class_destroy(sysdev.class);
	cdev_del(&sysdev.cdev);
	unregister_chrdev_region(sysdev.devt, 1);
	kfree(sysdev.snapshot);
	pr_info(DRIVER_NAME ": unloaded\n");
}

module_init(sysmetrics_init);
module_exit(sysmetrics_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Varun Adithya");
MODULE_DESCRIPTION("Read-only system metrics character device");
MODULE_VERSION("2.0");
