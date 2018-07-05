/*-
 * Copyright (c) 2018 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <fs/devfs/devfs_int.h>

#include "dl_assert.h"
#include "dl_utils.h"
#include "harness.h"
#include "dlog_client.h"

extern uint32_t hashlittle(const void *, size_t, uint32_t);

static void harness_cleanup(void *);

static int harness_init(void);
static void harness_fini(void);

static int harness_event_handler(struct module *, int, void *);

static char const * const HARNESS_NAME = "harness";

static d_open_t harness_open;
static d_close_t harness_close;
static d_write_t harness_write;
static d_ioctl_t harness_ioctl;

static struct cdevsw harness_cdevsw = {
	.d_version = D_VERSION,
	.d_open = harness_open,
	.d_close = harness_close,
	.d_ioctl = harness_ioctl,
	.d_write = harness_write,
	.d_name = HARNESS_NAME,
};

static struct cdev *harness_dev;

static int 
harness_init()
{
	struct make_dev_args harness_args;
	int e;

	make_dev_args_init(&harness_args);
	harness_args.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	harness_args.mda_devsw = &harness_cdevsw;
	harness_args.mda_uid = UID_ROOT;
	harness_args.mda_gid = GID_WHEEL;
	harness_args.mda_mode = S_IRUSR | S_IWUSR;

	e = make_dev_s(&harness_args, &harness_dev, HARNESS_NAME);
	DL_ASSERT(e != 0, ("Failed to create harness device"));

	return 0;
}

static void 
harness_fini()
{

	destroy_dev(harness_dev);
}

static int
harness_event_handler(struct module *module, int event, void *arg)
{
	int e = 0;

	switch(event) {
	case MOD_LOAD:
		DLOGTR0(PRIO_LOW, "Loading DLog kernel module\n");

		if (harness_init() != 0)
			e = EFAULT;
		break;
	case MOD_UNLOAD:
		DLOGTR0(PRIO_LOW, "Unloading DLog kernel module\n");

		harness_fini();
		break;
	default:
		e = EOPNOTSUPP;
		break;
	}

	return e;
}

static int 
harness_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{

	DLOGTR1(PRIO_LOW, "Opening the %s device.\n", HARNESS_NAME);
	return 0;
}

static int 
harness_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{

	DLOGTR1(PRIO_LOW, "Closing the %s device.\n", HARNESS_NAME);

	/* Clean up the associated private state (that is the DLog handle,
	 * if configured).
	 */
	devfs_clear_cdevpriv();
	return 0;	
}

static int 
harness_write(struct cdev *dev, struct uio *uio, int flag)
{
	struct dlog_handle *handle;
	struct iovec *key = &uio->uio_iov[0], *value = &uio->uio_iov[1];
	int rc;

	if (uio->uio_iovcnt != 2)
		return EINVAL;

	if (devfs_get_cdevpriv((void **) &handle) != 0)
		return EFAULT;

	rc = dlog_produce(handle, key->iov_base, key->iov_len,
	    value->iov_base, value->iov_len);
	if (rc != 0) {
		DLOGTR1(PRIO_HIGH,
		    "Failed producing message to DLog (%d)\n", rc);
		return -1;
	}

	DLOGTR0(PRIO_LOW, "Succeeded producing message to DLog\n");
	return 0;
}

static int 
harness_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct cdev_privdata *p;
	struct dlog_handle *handle;
	struct file *fp;
	struct filedesc *fdp = curproc->p_fd;
	int **pdlog = (int **) addr;
	int dlog;

	switch(cmd) {
	case HARNESSIOC_REGDLOG:

		/* Copyin the description of the client configuration. */
		if (copyin((void *) *pdlog, &dlog, sizeof(int)) != 0)
			return EFAULT; 

		/* Convert the DLog file descriptor into a struct dlog_handle */
		FILEDESC_SLOCK(fdp);
		fp = fget_locked(fdp, dlog);
		if (fp == NULL) {
			DLOGTR0(PRIO_HIGH, "File descriptor is invalid\n");
			return EINVAL;
		}
		
		FILEDESC_SUNLOCK(fdp);
		p = fp->f_cdevpriv;
		if (p == NULL) {
			DLOGTR0(PRIO_HIGH, "No DLog private data found\n");
			return EINVAL;
		}

		handle = (struct dlog_handle *) p->cdpd_data;
		if (handle == NULL) {
			DLOGTR0(PRIO_HIGH, "No DLog handle in private data\n");
			return EINVAL;
		}

		/* Associate the the DLog client handle with the device file. */
		if (devfs_set_cdevpriv(handle, harness_cleanup) != 0) {

			DLOGTR0(PRIO_HIGH,
			    "Error associating the DLog client handle.\n");
			return -1;
		}
		break;
	default:
		return -1;
	}
	return 0;
}

static void
harness_cleanup(void *arg)
{
}

DEV_MODULE(harness, harness_event_handler, NULL);
MODULE_VERSION(harness, 1);
MODULE_DEPEND(konsumer, dlog, 1, 1, 1);
