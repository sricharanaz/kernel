#ifndef __QCOM_SMD_H__
#define __QCOM_SMD_H__

#include <linux/device.h>
#include <linux/mod_devicetable.h>
#include <linux/rpmsg.h>

struct qcom_smd;
struct qcom_smd_channel;
struct qcom_smd_lookup;

#if IS_ENABLED(CONFIG_QCOM_SMD)

struct qcom_smd_channel *qcom_smd_open_channel(struct qcom_smd_channel *channel,
					       const char *name,
					       rpmsg_rx_cb_t cb);
void *qcom_smd_get_drvdata(struct qcom_smd_channel *channel);
void qcom_smd_set_drvdata(struct qcom_smd_channel *channel, void *data);
int qcom_smd_send(struct rpmsg_channel *channel, const void *data,
		  int len, bool wait);

#else

static inline struct qcom_smd_channel *
qcom_smd_open_channel(struct qcom_smd_channel *channel,
		      const char *name,
		      rpmsg_rx_cb_t cb)
{
	/* This shouldn't be possible */
	WARN_ON(1);
	return NULL;
}

void *qcom_smd_get_drvdata(struct qcom_smd_channel *channel)
{
	/* This shouldn't be possible */
	WARN_ON(1);
	return NULL;
}

void qcom_smd_set_drvdata(struct qcom_smd_channel *channel, void *data)
{
	/* This shouldn't be possible */
	WARN_ON(1);
}

static inline int qcom_smd_send(struct rpmsg_channel *rpdev,
				const void *data, int len, bool wait)
{
	/* This shouldn't be possible */
	WARN_ON(1);
	return -ENXIO;
}

#endif

#define module_qcom_smd_driver(__smd_driver) \
	module_driver(__smd_driver, qcom_smd_driver_register, \
		      qcom_smd_driver_unregister)


#endif
