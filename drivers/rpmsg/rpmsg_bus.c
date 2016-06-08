/*
 * Generic remote processor messaging bus
 *
 * Copyright (C) 2011 Texas Instruments, Inc.
 * Copyright (C) 2011 Google, Inc.
 *
 * Ohad Ben-Cohen <ohad@wizery.com>
 * Brian Swetland <swetland@google.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/rpmsg.h>
#include <linux/mutex.h>

/* sysfs show configuration fields */
#define rpmsg_show_attr(field, path, format_string)			\
static ssize_t								\
field##_show(struct device *dev,					\
			struct device_attribute *attr, char *buf)	\
{									\
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);		\
									\
	return sprintf(buf, format_string, path);			\
}

/* for more info, see Documentation/ABI/testing/sysfs-bus-rpmsg */
rpmsg_show_attr(name, rpdev->id.name, "%s\n");
rpmsg_show_attr(src, rpdev->src, "0x%x\n");
rpmsg_show_attr(dst, rpdev->dst, "0x%x\n");
rpmsg_show_attr(announce, rpdev->announce ? "true" : "false", "%s\n");


static ssize_t modalias_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);

	return sprintf(buf, RPMSG_DEVICE_MODALIAS_FMT "\n", rpdev->id.name);
}

static struct device_attribute rpmsg_dev_attrs[] = {
	__ATTR_RO(name),
	__ATTR_RO(modalias),
	__ATTR_RO(dst),
	__ATTR_RO(src),
	__ATTR_RO(announce),
	__ATTR_NULL
};

/* rpmsg devices and drivers are matched using the service name */
static inline int rpmsg_id_match(const struct rpmsg_channel *rpdev,
				  const struct rpmsg_device_id *id)
{
	return strncmp(id->name, rpdev->id.name, RPMSG_NAME_SIZE) == 0;
}

/* match rpmsg channel and rpmsg driver */
static int rpmsg_dev_match(struct device *dev, struct device_driver *drv)
{
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);
	struct rpmsg_driver *rpdrv = to_rpmsg_driver(drv);
	const struct rpmsg_device_id *ids = rpdrv->id_table;
	unsigned int i;

	for (i = 0; ids[i].name[0]; i++) {
		if (rpmsg_id_match(rpdev, &ids[i]))
			return 1;
	}
	return 0;
}

static int rpmsg_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);

	return add_uevent_var(env, "MODALIAS=" RPMSG_DEVICE_MODALIAS_FMT,
					rpdev->id.name);
}

/*
 * when an rpmsg driver is probed with a channel, we seamlessly create
 * it an endpoint, binding its rx callback to a unique local rpmsg
 * address.
 *
 * if we need to, we also announce about this channel to the remote
 * processor (needed in case the driver is exposing an rpmsg service).
 */
static int rpmsg_dev_probe(struct device *dev)
{
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);
	struct rpmsg_driver *rpdrv = to_rpmsg_driver(rpdev->dev.driver);
	int err;

	err = rpdev->pre_init(rpdev);
	if (err)
		goto out;

	err = rpdrv->probe(rpdev);
	if (err)
		dev_err(dev, "%s: failed: %d\n", __func__, err);

	err = rpdev->post_init(rpdev, err);

out:
	return err;
}

static int rpmsg_dev_remove(struct device *dev)
{
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);
	struct rpmsg_driver *rpdrv = to_rpmsg_driver(rpdev->dev.driver);
	int ret;

	ret = rpdev->pre_rem(rpdev);
	rpdrv->remove(rpdev);
	rpdev->post_rem(rpdev);

	return ret;
}

static struct bus_type rpmsg_bus = {
	.name		= "rpmsg",
	.match		= rpmsg_dev_match,
	.dev_attrs	= rpmsg_dev_attrs,
	.uevent		= rpmsg_uevent,
	.probe		= rpmsg_dev_probe,
	.remove		= rpmsg_dev_remove,
};

/**
 * __register_rpmsg_driver() - register an rpmsg driver with the rpmsg bus
 * @rpdrv: pointer to a struct rpmsg_driver
 * @owner: owning module/driver
 *
 * Returns 0 on success, and an appropriate error value on failure.
 */
int __register_rpmsg_driver(struct rpmsg_driver *rpdrv, struct module *owner)
{
	int ret;

	rpdrv->drv.bus = &rpmsg_bus;
	rpdrv->drv.owner = owner;

	ret = driver_register(&rpdrv->drv);

	return ret;
}
EXPORT_SYMBOL(__register_rpmsg_driver);

/**
 * unregister_rpmsg_driver() - unregister an rpmsg driver from the rpmsg bus
 * @rpdrv: pointer to a struct rpmsg_driver
 *
 * Returns 0 on success, and an appropriate error value on failure.
 */
void unregister_rpmsg_driver(struct rpmsg_driver *rpdrv)
{
	driver_unregister(&rpdrv->drv);
}
EXPORT_SYMBOL(unregister_rpmsg_driver);

static void rpmsg_release_device(struct device *dev)
{
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);

	kfree(rpdev);
}

int rpmsg_create_channel(void *chptr, struct rpmsg_channel_info chinfo)
{
	struct rpmsg_channel *rpdev;
	int ret = 0;

	rpdev = kzalloc(sizeof(struct rpmsg_channel), GFP_KERNEL);
	if (!rpdev) {
		pr_err("kzalloc failed\n");
		return -ENOMEM;
	}

	rpdev->pre_init = chinfo.pre_init;
	rpdev->post_init = chinfo.post_init;
	rpdev->pre_rem = chinfo.pre_rem;
	rpdev->post_rem = chinfo.post_rem;

	ret = chinfo.chinit(rpdev, chptr, &chinfo);
	if (ret) {
		kfree(rpdev);
		return ret;
	}

        rpdev->dev.bus = &rpmsg_bus;
        rpdev->dev.release = rpmsg_release_device;
        strncpy(rpdev->id.name, chinfo.name, RPMSG_NAME_SIZE);

        ret = device_register(&rpdev->dev);

        if (ret) {
                dev_err(&rpdev->dev, "device_register failed: %d\n", ret);
                put_device(&rpdev->dev);
		return -ENODEV;
	}

	return 0;
}
EXPORT_SYMBOL(rpmsg_create_channel);

/*
 * find an existing channel using its name + address properties,
 * and destroy it
 */
int rpmsg_destroy_channel(struct rpmsg_channel *rpdev)
{
	device_unregister(&rpdev->dev);
	put_device(&rpdev->dev);
	return 0;
}
EXPORT_SYMBOL(rpmsg_destroy_channel);

static int __init rpmsg_init(void)
{
	int ret;

	ret = bus_register(&rpmsg_bus);
	if (ret) {
		pr_err("failed to register rpmsg bus: %d\n", ret);
		return ret;
	}

	return ret;
}
postcore_initcall(rpmsg_init);

static void __exit rpmsg_exit(void)
{
	bus_unregister(&rpmsg_bus);
}
module_exit(rpmsg_exit);

MODULE_DESCRIPTION("remote processor messaging bus");
MODULE_LICENSE("GPL v2");
