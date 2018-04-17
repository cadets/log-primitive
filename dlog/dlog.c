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
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/ioccom.h>
#include <sys/stat.h>

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_memory.h"
#include "dl_utils.h"
#include "dlog_client.h"

static void * dl_alloc(unsigned long len);
static int dlog_event_handler(struct module *, int, void *);
static void dl_free(void *addr);
static d_open_t dlog_open;
static d_close_t dlog_close;
static d_ioctl_t dlog_ioctl;
static void dl_client_close(void *);

static char const * const DLOG_NAME = "dlog";

struct proc *dlog_client_proc;

static struct cdevsw dlog_cdevsw = {
	.d_version = D_VERSION,
	.d_open = dlog_open,
	.d_close = dlog_close,
	.d_ioctl = dlog_ioctl,
	.d_name = DLOG_NAME,
};

static struct cdev *dlog_dev;

const dlog_malloc_func dlog_alloc = dl_alloc;
const dlog_free_func dlog_free = dl_free;

MALLOC_DECLARE(M_DLOG);
MALLOC_DEFINE(M_DLOG, "dlog", "DLog memory");
	
#define DLOGIOC_PRODUCER _IOWR('d', 1, struct dl_client_config)

static void
dl_free(void *addr)
{

	return free(addr, M_DLOG);
}

static void *
dl_alloc(unsigned long len)
{

	return malloc(len, M_DLOG, M_NOWAIT);
}

static int
dlog_event_handler(struct module *module, int event, void *arg)
{
	struct make_dev_args dlog_args;
	int e = 0;

	switch(event) {
	case MOD_LOAD:
		DLOGTR0(PRIO_LOW, "Loading DLog kernel module\n");

		make_dev_args_init(&dlog_args);
		dlog_args.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
		dlog_args.mda_devsw = &dlog_cdevsw;
		dlog_args.mda_uid = UID_ROOT;
		dlog_args.mda_gid = GID_WHEEL;
		dlog_args.mda_mode = S_IRUSR | S_IWUSR;

		e = make_dev_s(&dlog_args, &dlog_dev, DLOG_NAME);
		break;
	case MOD_UNLOAD:
		DLOGTR0(PRIO_LOW, "Unloading DLog kernel module\n");

		destroy_dev(dlog_dev);
		break;
	default:
		e = EOPNOTSUPP;
		break;
	}

	return e;
}

static int 
dlog_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{

	DLOGTR0(PRIO_LOW, "Opening the DLog device.\n");
	return 0;
}

static int 
dlog_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{

	DLOGTR0(PRIO_LOW, "Closing the DLog device.\n");

	/* Clean up the associated private state (that is the DLog handle,
	 * if configured).
	 */
	devfs_clear_cdevpriv();
	return 0;	
}

static int 
dlog_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct dl_client_config *conf;
	struct dl_client_config_desc conf_desc;
	struct dl_client_config_desc **pconf_desc =
	    (struct dl_client_config_desc **) addr;
	struct dlog_handle *handle;
	nvlist_t *props;
	void *packed_nvlist;

	switch(cmd) {
	case DLOGIOC_PRODUCER:
		DLOGTR0(PRIO_LOW, "Configuring DLog producer.\n");

		if (copyin((void *) *pconf_desc, &conf_desc,
		    sizeof(struct dl_client_config_desc)) != 0)
			return EFAULT; 

		packed_nvlist = dlog_alloc(conf_desc.dlcc_packed_nvlist_len);
		DL_ASSERT(packed_nvlist != NULL,
		    ("Failed allocating memory for the nvlist.")); 

		if (copyin(conf_desc.dlcc_packed_nvlist, packed_nvlist,
		    conf_desc.dlcc_packed_nvlist_len) != 0)
			return EFAULT; 

		/* Unpack the nvlist of properties used for configuring the
		 * DLog client instance.
		 */
		props = nvlist_unpack(packed_nvlist,
		    conf_desc.dlcc_packed_nvlist_len, 0); 
		// TODO: error handling
	
		dlog_free(packed_nvlist);

		/* Open the DLog client with the specified properties. */
		conf = (struct dl_client_config *) dlog_alloc(
		    sizeof(struct dl_client_config));
		DL_ASSERT(conf != NULL,
		    ("Failed allocating DLog client configuration."));
		conf->dlcc_on_response = conf_desc.dlcc_on_response;;
		conf->dlcc_props = props;

		handle = dlog_client_open(conf);
		if (handle == NULL) {

			DLOGTR0(PRIO_HIGH, "Error opening Dlog client.\n");
			dlog_free(conf);
			return EFAULT;
		}

		/* Associate the the DLog client handle with the device file. */
		if (devfs_set_cdevpriv(handle, dl_client_close) != 0) {

			DLOGTR0(PRIO_HIGH,
			    "Error associtaing the DLog client handle.\n");
			dlog_client_close(handle);
			dlog_free(conf);
			return EFAULT;
		}
		break;
	default:
		return -1;
	}
	return 0;
}

static void
dl_client_close(void *arg)
{
	struct dlog_handle *handle = (struct dlog_handle *) arg;

	DL_ASSERT(handle != NULL, ("DLog client handle cannot be NULL."));
	dlog_client_close(handle);
}

DEV_MODULE(dlog, dlog_event_handler, NULL);
MODULE_VERSION(dlog, 1);
