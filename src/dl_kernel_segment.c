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
 * ar	 met:
 *1. Redistributions of source code must retain the above copyright
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
#include <sys/uio.h>
#include <sys/capsicum.h>
#include <sys/syscallsubr.h>
#include <sys/vnode.h>
#include <sys/unistd.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_kernel_segment.h"
#include "dl_kernel_segment.h"
#include "dl_segment.h"
#include "dl_utils.h"

struct dl_kernel_segment {
	struct dl_segment dlks_segment;
	SLIST_ENTRY(dl_segment) dlks_entries;
	struct mtx dlks_lock; /* Lock for whilst updating segment. */
	struct file *dlks_log;
	uint32_t dlks_offset;
};

static void dlks_lock(struct dl_segment *);
static void dlks_unlock(struct dl_segment *);
static int dlks_insert_message(struct dl_segment *, struct dl_bbuf *);
static int dlks_get_message_by_offset(struct dl_segment *, int,
    struct dl_bbuf **);
static uint32_t dlks_get_offset(struct dl_segment *);
static int dlks_sync(struct dl_segment *);
static int dlks_get_log(struct dl_segment *);

/**
 * Check the integrity of a KernelSegment instance.
 *
 * @param self KernelSegment instance.
 */
static inline void dl_kernel_segment_check_integrity(
    struct dl_kernel_segment *self)
{

	DL_ASSERT(self != NULL, ("KernelSegment instance cannot be NULL."));
	DL_ASSERT(self->dlks_log != NULL, ("KernelSegment file cannot be NULL."));
}

/**
 * KernelSegment destructor.
 *
 * @param self KernelSegment instance.
 */
void
dl_kernel_segment_delete(struct dl_kernel_segment *self)
{
	struct thread *td = curthread;

	dl_kernel_segment_check_integrity(self);

	mtx_destroy(&(self->dlks_lock));
	/* Decrease the reference count on the file. */
	fdrop(self->dlks_log, td);
	dlog_free(self);
}

/**
 * Static factory methof for constructing a KernelSegment from a SegmentDescription.
 *
 * @param self KernelSegment instance.
 * @param seg_desc KernelSegment instance.
 * @return 0 is successful, -1 otherwise
 */
int
dl_kernel_segment_from_desc(struct dl_kernel_segment **self,
    struct dl_segment_desc *seg_desc)
{
	struct thread *td = curthread;
	cap_rights_t rights;
	struct dl_kernel_segment *kseg;
	struct vnode *vp;
	int rc;

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL"));	
	DL_ASSERT(seg_desc != NULL, ("SegmentDesc instance cannot be NULL"));	

	kseg = (struct dl_kernel_segment *) dlog_alloc(
	    sizeof(struct dl_kernel_segment));
	DL_ASSERT(kseg != NULL, ("Failed allocating KernelSegment instance"));
	if (kseg == NULL)
		goto err_kseg_ctor;

	bzero(kseg, sizeof(struct dl_kernel_segment));

	/* Initalise the KernelSegment super class. */
	rc = dl_segment_new(&kseg->dlks_segment,
	    seg_desc->dlsd_log,
	    seg_desc->dlsd_base_offset,
	    seg_desc->dlsd_size,
	    dlks_insert_message,
	    dlks_get_message_by_offset,
	    dlks_get_offset,
	    dlks_lock,
	    dlks_unlock,
	    dlks_sync);
	if (rc != 0) {

		DLOGTR0(PRIO_HIGH,
		    "KernelSegment vnode is TODO.\n");
		goto err_kseg_free;
	}

	/* Set the KernelSegment offset */
	kseg->dlks_offset = seg_desc->dlsd_offset;

	/* Verify write permission for the file descriptor */
	rc = fget_write(td, seg_desc->dlsd_log,
	    cap_rights_init(&rights, CAP_WRITE), &kseg->dlks_log); 
	if (rc != 0) {

		DLOGTR0(PRIO_HIGH,
		    "Lacking write permission to log file descriptor.\n");
		goto err_kseg_free;
	}

	/* Check that it is a regular file. */
	if (kseg->dlks_log->f_type != DTYPE_VNODE) {

		DLOGTR0(PRIO_HIGH,
		    "KernelSegment log file descriptor is not a regular file.\n");
		goto err_kseg_free;
	}

	/* Check that the vnode is non-NULL */
	vp = kseg->dlks_log->f_vnode;
	if (vp != NULL && vp->v_type != VREG) {

		DLOGTR0(PRIO_HIGH,
		    "KernelSegment vnode is NULL or not a regular file.\n");
		goto err_kseg_free;
	}

	/* Check if the number of clients using the node and
	 * the number of clients vetoing recyling of
	 * the vnode are zero.
	 */
	if (vp->v_usecount == 0 && vp->v_holdcnt == 0) {

		DLOGTR0(PRIO_HIGH,
		    "KernelSegment vnode is TODO.\n");
		goto err_kseg_free;
	}

	mtx_init(&kseg->dlks_lock, NULL, "KernelSegment", MTX_DEF);

	dl_kernel_segment_check_integrity(kseg);
	*self = kseg;

	return 0;

err_kseg_free:
	dlog_free(kseg);

err_kseg_ctor:
	DLOGTR0(PRIO_HIGH, "Failed allocating KernelSegment instance\n");

	return -1;
}

static int
dlks_insert_message(struct dl_segment *super, struct dl_bbuf *buffer)
{
	struct mount *mp;
	struct thread *td = curthread;
	struct uio u;
	struct iovec log_bufs[1];
	struct vnode *vp;
	struct dl_kernel_segment *self = (struct dl_kernel_segment *) super;
	int rc;

	dl_kernel_segment_check_integrity(self);
	DL_ASSERT(buffer != NULL,
	    ("Buffer to insert into segment cannot be NULL."));

	dlks_lock(super);

	/* Update the log file. */
	log_bufs[0].iov_base = dl_bbuf_data(buffer);
	log_bufs[0].iov_len = dl_bbuf_pos(buffer);

	bzero(&u, sizeof(struct uio));
	u.uio_iov = log_bufs;
	u.uio_iovcnt = 1;
	u.uio_offset = -1;
        u.uio_resid = log_bufs[0].iov_len;
        u.uio_segflg  = UIO_SYSSPACE;
        u.uio_rw = UIO_WRITE;
        u.uio_td = td;

	/* Check that the vnode is non-NULL and is a regular file */
	vp = self->dlks_log->f_vnode;
	if (vp != NULL && vp->v_type != VREG) {

		DLOGTR0(PRIO_HIGH,
		    "KernelSegment vnode is NULL or not a regular file.\n");
		return -1;
	}

	/* Check if the number of clients using the node and
	 * the number of clients vetoing recyling of
	 * the vnode are zero.
	 */
	if (vp->v_usecount == 0 && vp->v_holdcnt == 0) {

		DLOGTR0(PRIO_HIGH,
		    "KernelSegment vnode is TODO.\n");
		return -1;
	}

	/* Write to the vnode.
	 * Assume that each operation is successfull as there is very little
	 * error recovery that can be done should an individual operation fail.
	 */
	rc = vn_start_write(vp, &mp, V_WAIT);
	rc |= VOP_LOCK(vp, LK_EXCLUSIVE | LK_RETRY);
	rc |= VOP_WRITE(vp, &u, IO_UNIT | IO_APPEND, self->dlks_log->f_cred);
	rc |= VOP_UNLOCK(vp, 0);
	vn_finished_write(mp);

	if (rc == 0) {

		/* Update the offset. */
		self->dlks_offset++;
	}

	dlks_unlock(super);
	return rc;
}

static int
dlks_get_message_by_offset(struct dl_segment *super, int offset,
    struct dl_bbuf **msg_buf)
{
	/* Unimplemented. */
	return -1;
}

static void
dlks_lock(struct dl_segment *super) __attribute((no_thread_safety_analysis))
{
	struct dl_kernel_segment *self = (struct dl_kernel_segment *) super;

	dl_kernel_segment_check_integrity(self);
	mtx_lock(&self->dlks_lock);
}

static void
dlks_unlock(struct dl_segment *seg) __attribute((no_thread_safety_analysis))
{
	struct dl_kernel_segment *self = (struct dl_kernel_segment *) self;

	dl_kernel_segment_check_integrity(self);
	mtx_unlock(&self->dlks_lock);
}

static uint32_t 
dlks_get_offset(struct dl_segment *super)
{
	struct dl_kernel_segment *self = (struct dl_kernel_segment *) super;

	dl_kernel_segment_check_integrity(self);
	return self->dlks_offset;
}

/**
 * Method for syncing the KernelSegment's vnode.
 *
 * @param self KernelSegment instance.
 * @return 0 is success, otherwise an error code
 */
static int
dlks_sync(struct dl_segment *super)
{
	struct dl_kernel_segment *self = (struct dl_kernel_segment *) super;
	struct mount *mp;
	struct vnode *vp;
	int rc;

	dl_kernel_segment_check_integrity(self);

	/* Check that the vnode is non-NULL and is a regular file */
	vp = self->dlks_log->f_vnode;
	if (vp != NULL && vp->v_type != VREG) {

		DLOGTR0(PRIO_HIGH,
		    "KernelSegment vnode is NULL or not a regular file.\n");
		return -1;
	}

	/* Sync the vnode.
	 * Assume that each operation is successfull as there is very little
	 * error recovery that can be done should an individual operation fail.
	 */
	rc = vn_start_write(vp, &mp, V_WAIT);
	rc |= VOP_LOCK(vp, LK_EXCLUSIVE | LK_RETRY);
	rc |= VOP_FSYNC(vp, MNT_WAIT, curthread);
	rc |= VOP_UNLOCK(vp, 0);
	vn_finished_write(mp);

	return rc;
}
