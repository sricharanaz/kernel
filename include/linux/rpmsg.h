/*
 * Remote processor messaging
 *
 * Copyright (C) 2011 Texas Instruments, Inc.
 * Copyright (C) 2011 Google, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name Texas Instruments nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _LINUX_RPMSG_H
#define _LINUX_RPMSG_H

#include <linux/types.h>
#include <linux/device.h>
#include <linux/mod_devicetable.h>
#include <linux/kref.h>
#include <linux/mutex.h>

#define to_rpmsg_channel(d) container_of(d, struct rpmsg_channel, dev)
#define to_rpmsg_driver(d) container_of(d, struct rpmsg_driver, drv)

/**
 * rpmsg_channel - devices that belong to the rpmsg bus are called channels
 * @channel: Pointer to channel type specific structure
 * @dev: the device struct
 * @send: Channel specific transmit function
 * @pre_init: callback before calling the channel probe
 * @post_init: callback after calling the channel probe
 * @pre_rem: callback before calling channel remove
 * @post_rem: callback after calling channel remove
 * @priv: Pointer to private data that clients use
 * @id: device id (used to match between rpmsg drivers and devices)
 * @src: local address, not all channel provides will need this
 * @dst: destination address, not all channel provides will need this
 * @announce: if set, rpmsg will announce the creation/removal of this channel
 */
struct rpmsg_channel {
	void *channel;
	struct device dev;
	int (*send) (struct rpmsg_channel *rpdev, const void *data, int len,
		     bool wait);
	int (*sendto) (struct rpmsg_channel *rpdev, int dst, const void *data,
		       int len, bool wait);
	int (*sendoff) (struct rpmsg_channel *rpdev, int src, int dst,
			const void *data, int len, bool wait);
	int (*pre_init) (void *);
	int (*post_init) (void *, int);
	int (*pre_rem) (void *);
	void (*post_rem) (void *);
	void *priv;
	struct rpmsg_device_id id;
	u32 src;
	u32 dst;
	bool announce;
};

/**
 * struct rpmsg_channel_info - internal channel info representation
 * @chinit: callback to do channel specific initialisation.
 * @pre_init: callback to be called before channel probe
 * @post_init: callback to be called after channel probe
 * @pre_rem: callback to be called before channel remove
 * @post_rem: callback to be called after channel remove
 * @name: name of service
 * @src: local address
 * @dst: destination address
 */
struct rpmsg_channel_info {
	int (*chinit) (struct rpmsg_channel *rpdev,
		       void *ptr,
		       struct rpmsg_channel_info *chinfo);
	int (*pre_init) (void *);
	int (*post_init) (void *, int);
	int (*pre_rem) (void *);
	void (*post_rem) (void *);
	char name[RPMSG_NAME_SIZE];
	u32 src;
	u32 dst;
};

typedef void (*rpmsg_rx_cb_t)(struct rpmsg_channel *, void *, int, void *, u32);

/**
 * struct rpmsg_driver - rpmsg driver struct
 * @drv: underlying device driver
 * @id_table: rpmsg ids serviced by this driver
 * @probe: invoked when a matching rpmsg channel (i.e. device) is found
 * @remove: invoked when the rpmsg channel is removed
 * @callback: invoked when an inbound message is received on the channel
 */
struct rpmsg_driver {
	struct device_driver drv;
	const struct rpmsg_device_id *id_table;
	int (*probe)(struct rpmsg_channel *dev);
	void (*remove)(struct rpmsg_channel *dev);
	void (*callback)(struct rpmsg_channel *, void *, int, void *, u32);
};

int register_rpmsg_device(struct rpmsg_channel *dev);
void unregister_rpmsg_device(struct rpmsg_channel *dev);
int __register_rpmsg_driver(struct rpmsg_driver *drv, struct module *owner);
void unregister_rpmsg_driver(struct rpmsg_driver *drv);

/* use a macro to avoid include chaining to get THIS_MODULE */
#define register_rpmsg_driver(drv) \
	__register_rpmsg_driver(drv, THIS_MODULE)


/**
 * module_rpmsg_driver() - Helper macro for registering an rpmsg driver
 * @__rpmsg_driver: rpmsg_driver struct
 *
 * Helper macro for rpmsg drivers which do not do anything special in module
 * init/exit. This eliminates a lot of boilerplate.  Each module may only
 * use this macro once, and calling it replaces module_init() and module_exit()
 */
#define module_rpmsg_driver(__rpmsg_driver) \
	module_driver(__rpmsg_driver, register_rpmsg_driver, \
			unregister_rpmsg_driver)

/**
 * rpmsg_send() - send a message across to the remote processor
 * @rpdev: the rpmsg channel
 * @data: payload of message
 * @len: length of payload
 *
 * This function sends @data of length @len on the @rpdev channel.
 * The message will be sent to the remote processor which the @rpdev
 * channel belongs to, using @rpdev's source and destination addresses.
 * In case there are no TX buffers available, the function will block until
 * one becomes available, or a timeout of 15 seconds elapses. When the latter
 * happens, -ERESTARTSYS is returned.
 *
 * Can only be called from process context (for now).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
static inline int rpmsg_send(struct rpmsg_channel *rpdev, void *data, int len)
{
	return rpdev->send(rpdev, data, len, true);
}

/**
 * rpmsg_sendto() - send a message across to the remote processor, specify dst
 * @rpdev: the rpmsg channel
 * @data: payload of message
 * @len: length of payload
 * @dst: destination address
 *
 * This function sends @data of length @len to the remote @dst address.
 * The message will be sent to the remote processor which the @rpdev
 * channel belongs to, using @rpdev's source address.
 * In case there are no TX buffers available, the function will block until
 * one becomes available, or a timeout of 15 seconds elapses. When the latter
 * happens, -ERESTARTSYS is returned.
 *
 * Can only be called from process context (for now).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
static inline
int rpmsg_sendto(struct rpmsg_channel *rpdev, void *data, int len, u32 dst)
{
	return rpdev->sendto(rpdev, dst, data, len, true);
}

/**
 * rpmsg_send_offchannel() - send a message using explicit src/dst addresses
 * @rpdev: the rpmsg channel
 * @src: source address
 * @dst: destination address
 * @data: payload of message
 * @len: length of payload
 *
 * This function sends @data of length @len to the remote @dst address,
 * and uses @src as the source address.
 * The message will be sent to the remote processor which the @rpdev
 * channel belongs to.
 * In case there are no TX buffers available, the function will block until
 * one becomes available, or a timeout of 15 seconds elapses. When the latter
 * happens, -ERESTARTSYS is returned.
 *
 * Can only be called from process context (for now).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
static inline
int rpmsg_send_offchannel(struct rpmsg_channel *rpdev, u32 src, u32 dst,
							void *data, int len)
{
	return rpdev->sendoff(rpdev, src, dst, data, len, true);
}

/**
 * rpmsg_send() - send a message across to the remote processor
 * @rpdev: the rpmsg channel
 * @data: payload of message
 * @len: length of payload
 *
 * This function sends @data of length @len on the @rpdev channel.
 * The message will be sent to the remote processor which the @rpdev
 * channel belongs to, using @rpdev's source and destination addresses.
 * In case there are no TX buffers available, the function will immediately
 * return -ENOMEM without waiting until one becomes available.
 *
 * Can only be called from process context (for now).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
static inline
int rpmsg_trysend(struct rpmsg_channel *rpdev, void *data, int len)
{
	return rpdev->send(rpdev, data, len, false);
}

/**
 * rpmsg_sendto() - send a message across to the remote processor, specify dst
 * @rpdev: the rpmsg channel
 * @data: payload of message
 * @len: length of payload
 * @dst: destination address
 *
 * This function sends @data of length @len to the remote @dst address.
 * The message will be sent to the remote processor which the @rpdev
 * channel belongs to, using @rpdev's source address.
 * In case there are no TX buffers available, the function will immediately
 * return -ENOMEM without waiting until one becomes available.
 *
 * Can only be called from process context (for now).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
static inline
int rpmsg_trysendto(struct rpmsg_channel *rpdev, void *data, int len, u32 dst)
{
	return rpdev->sendto(rpdev, dst, data, len, false);
}

/**
 * rpmsg_send_offchannel() - send a message using explicit src/dst addresses
 * @rpdev: the rpmsg channel
 * @src: source address
 * @dst: destination address
 * @data: payload of message
 * @len: length of payload
 *
 * This function sends @data of length @len to the remote @dst address,
 * and uses @src as the source address.
 * The message will be sent to the remote processor which the @rpdev
 * channel belongs to.
 * In case there are no TX buffers available, the function will immediately
 * return -ENOMEM without waiting until one becomes available.
 *
 * Can only be called from process context (for now).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
static inline
int rpmsg_trysend_offchannel(struct rpmsg_channel *rpdev, u32 src, u32 dst,
			     void *data, int len)
{
	return rpdev->sendoff(rpdev, src, dst, data, len, false);
}

/**
 * rpmsg_create_channel() - Create a new rpmsg channel
 * @chptr: Channel specific pointer passed to the channel init callback
 * @chinfo: Channel specific details
 */
int rpmsg_create_channel(void *chptr, struct rpmsg_channel_info chinfo);

int rpmsg_destroy_channel(struct rpmsg_channel *rpdev);

#endif /* _LINUX_RPMSG_H */
