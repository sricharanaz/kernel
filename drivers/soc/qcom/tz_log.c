/*
 * Copyright (c) 2015-2017, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/debugfs.h> /* this is for DebugFS libraries */
#include <linux/fs.h>
#include <linux/dma-mapping.h>
#include <linux/qcom_scm.h>
#include <linux/slab.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/irq.h>
#include <linux/platform_device.h>

/* Maximum size for buffers to support AARCH64 TZ */
#define BUF_LEN 0x2000

#define TZ_INFO_GET_DIAG_ID 0x2

struct dentry *dirret, *fileret;

static char ker_buf[BUF_LEN] __aligned(8192), tmp_buf[BUF_LEN];

/* Read file operation */
static ssize_t tz_log_read(struct file *fp, char __user *user_buffer,
				size_t count, loff_t *position)
{
	int ret;
	uint16_t offset;
	uint16_t ring;
	uint32_t buf_len;
	uint32_t *ring_off;
	struct tzbsp_diag_log_t *log;
	uint16_t wrap;

	/* SCM call to TZ to get the tz log */
	ret = qcom_scm_tz_log(SCM_SVC_INFO, TZ_INFO_GET_DIAG_ID, ker_buf,
				&buf_len, &ring_off, &log);
	if (ret != 0) {
		pr_err("Error in getting tz log\n");
		return -EINVAL;
	}

	offset = log->log_pos.offset;
	ring = *ring_off;
	wrap = log->log_pos.wrap;

	if (wrap != 0) {
		memcpy(tmp_buf, (ker_buf + offset + ring),
					(buf_len - offset - ring));
		memcpy(tmp_buf + (buf_len - offset - ring), (ker_buf + ring),
					offset);
	} else {
		memcpy(tmp_buf, (ker_buf + ring), offset);
	}

	return simple_read_from_buffer(user_buffer, count,
					position, tmp_buf, buf_len);
}

static const struct file_operations fops_tz_log = {
	.read = tz_log_read,
};

static irqreturn_t tzerr_irq(int irq, void *data)
{
	panic("Access Violation!!!\n");
}

static int qca_tzlog_probe(struct platform_device *pdev)
{
	int filevalue;
	int irq;
	dirret = debugfs_create_dir("qcom_debug_logs", NULL);
	fileret = debugfs_create_file("tz_log", 0444, dirret,
					&filevalue, &fops_tz_log);

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(&pdev->dev, "unable to get tzlog interrupt\n");
		return -EIO;
	}

	devm_request_irq(&pdev->dev, irq, tzerr_irq,
				IRQF_ONESHOT, "tzerror", NULL);

	return 0;
}

static int qca_tzlog_remove(struct platform_device *pdev)
{
	/* removing the directory recursively which
	in turn cleans all the file */
	debugfs_remove_recursive(dirret);

	return 0;
}

static const struct of_device_id qca_tzlog_of_match[] = {
	{ .compatible = "qca,tzlog" },
	{}
};
MODULE_DEVICE_TABLE(of, qca_tzlog_of_match);

static struct platform_driver qca_tzlog_driver = {
	.probe = qca_tzlog_probe,
	.remove = qca_tzlog_remove,
	.driver  = {
		.name  = "qca_tzlog",
		.of_match_table = qca_tzlog_of_match,
	},
};
module_platform_driver(qca_tzlog_driver);
