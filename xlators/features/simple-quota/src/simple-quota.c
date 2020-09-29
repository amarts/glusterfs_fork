/*
   Copyright (c) 2020 Kadalu.IO <https://kadalu.io>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#include <glusterfs/glusterfs.h>
#include <glusterfs/xlator.h>
#include <glusterfs/logging.h>
#include <glusterfs/syncop.h>
#include <glusterfs/defaults.h>

#include "simple-quota.h"

#define QUOTA_USAGE_KEY "glusterfs.quota.total-usage"

static int64_t
sync_data_to_disk(xlator_t *this, sq_inode_t *ictx)
{
    int ret = -1;
    loc_t loc = {};

    if (!ictx || !ictx->ns) {
        return 0;
    }

    dict_t *dict = dict_new();
    if (!dict) {
        return ictx->xattr_size;
    }

    // int64_t value_on_disk = hton64(size);
    int64_t size = GF_ATOMIC_GET(ictx->pending_update);
    /* TODO: how do you get and set to 0? */
    GF_ATOMIC_INIT(ictx->pending_update, 0);
    int64_t value_on_disk = (ictx->xattr_size + size);
    ret = dict_set_int64(dict, SQUOTA_SIZE_KEY, value_on_disk);
    if (ret < 0) {
        dict_unref(dict);
        GF_ATOMIC_ADD(ictx->pending_update, size);
        return value_on_disk;
    }

    gf_log("quota2", GF_LOG_TRACE, "%s: Writing size of %" PRId64,
           uuid_utoa(ictx->ns->gfid), size);

    /* Send the request to actual gfid */
    loc.inode = inode_ref(ictx->ns);
    /* As we are doing only operation from server side */
    ret = syncop_setxattr(FIRST_CHILD(this), &loc, dict, 0, NULL, NULL);
    if (ret < 0) {
        /* FIXME: should I keep it here ? */
        GF_ATOMIC_ADD(ictx->pending_update, size);
        gf_log(this->name, GF_LOG_ERROR, "%s: Quota value update failed",
               uuid_utoa(ictx->ns->gfid));
    } else {
        ictx->xattr_size = value_on_disk;
    }

    inode_unref(ictx->ns);
    dict_unref(dict);

    return value_on_disk;
}

static void
sync_data_from_priv(xlator_t *this, sq_private_t *priv)
{
    sq_inode_t *tmp;
    sq_inode_t *tmp2;

    if (list_empty(&priv->ns_list)) {
        return;
    }
    /* TODO: the namespace inodes should flush thier sizes here */
    list_for_each_entry_safe(tmp, tmp2, &priv->ns_list, priv_list)
    {
        sync_data_to_disk(this, tmp);
        tmp = NULL;
    }
    return;
}

static uint64_t
sq_set_ns_hardlimit(xlator_t *this, inode_t *inode, int64_t limit, int64_t size,
                    bool set_ns)
{
    sq_private_t *priv = this->private;
    sq_inode_t *sq_ctx;
    uint64_t tmp_mq = 0;
    int ret = -1;

    sq_ctx = GF_MALLOC(sizeof(sq_inode_t), gf_common_mt_char);
    if (!sq_ctx)
        goto out;
    INIT_LIST_HEAD(&sq_ctx->priv_list);
    sq_ctx->hard_lim = limit;
    sq_ctx->xattr_size = size;
    sq_ctx->total_size = size; /* Initialize it to this number for now */
    GF_ATOMIC_INIT(sq_ctx->pending_update, 0);

    sq_ctx->ns = NULL;
    if (set_ns)
        sq_ctx->ns = inode;

    tmp_mq = (uint64_t)(unsigned long)sq_ctx;
    ret = inode_ctx_put(inode, this, tmp_mq);
    if (ret < 0) {
        GF_FREE(sq_ctx);
        tmp_mq = 0;
        goto out;
    }
    LOCK(&priv->lock);
    {
        list_add_tail(&sq_ctx->priv_list, &priv->ns_list);
    }
    UNLOCK(&priv->lock);

    gf_log(this->name, GF_LOG_INFO, "hardlimit set on %s (%ld, %ld)",
           uuid_utoa(inode->gfid), limit, size);
out:
    return tmp_mq;
}

static void
sq_update_namespace(xlator_t *this, inode_t *ns, struct iatt *prebuf,
                    struct iatt *postbuf, int64_t size)
{
    sq_inode_t *sq_ctx;
    uint64_t tmp_mq = 0;
    if (!ns)
        goto out;

    if (!size)
        size = (postbuf->ia_blocks - prebuf->ia_blocks) * 512;

    bool linked_inode = IATT_TYPE_VALID(ns->ia_type);
    inode_ctx_get(ns, this, &tmp_mq);
    if (!tmp_mq) {
        tmp_mq = sq_set_ns_hardlimit(this, ns, 0, size, linked_inode);
        if (!tmp_mq)
            goto out;
    }

    sq_ctx = (sq_inode_t *)(uintptr_t)tmp_mq;

    if (ns != sq_ctx->ns) {
        /* Set this, as it is possible to have linked a wrong
           inode pointer in lookup */
        sq_ctx->ns = ns;
    }

    GF_ATOMIC_ADD(sq_ctx->pending_update, size);
out:
    return;
}

static inline void
sq_update_total_usage(xlator_t *this, inode_t *inode, int64_t val)
{
    uint64_t tmp_mq = 0;

    inode_ctx_get(inode, this, &tmp_mq);
    if (!tmp_mq) {
        tmp_mq = sq_set_ns_hardlimit(this, inode, 0, 0, true);
        if (!tmp_mq)
            goto out;
    }
    sq_inode_t *sq_ctx = (sq_inode_t *)(uintptr_t)tmp_mq;
    sq_ctx->total_size = val;

    sync_data_to_disk(this, sq_ctx);

out:
    return;
}

static void
sq_update_hard_limit(xlator_t *this, inode_t *ns, int64_t limit, int64_t size)
{
    sq_inode_t *sq_ctx;
    uint64_t tmp_mq = 0;

    if (!ns)
        goto out;

    inode_ctx_get(ns, this, &tmp_mq);
    if (!tmp_mq) {
        tmp_mq = sq_set_ns_hardlimit(this, ns, limit, size,
                                     IATT_TYPE_VALID(ns->ia_type));
        if (!tmp_mq)
            goto out;
    }

    gf_log(this->name, GF_LOG_INFO, "hardlimit update: %s %ld %ld",
	   uuid_utoa(ns->gfid), limit, size);
    sq_ctx = (sq_inode_t *)(uintptr_t)tmp_mq;
    sq_ctx->hard_lim = limit;
    /* shouldn't come here with 'size > 0' */

out:
    return;
}

static int
sq_check_usage(xlator_t *this, inode_t *inode, size_t size)
{
    sq_inode_t *sq_ctx;
    uint64_t tmp_mq = 0;

    inode_ctx_get(inode, this, &tmp_mq);
    if (!tmp_mq)
        return 0;

    sq_ctx = (sq_inode_t *)(uintptr_t)tmp_mq;
    /* If hardlimit is not set, allow writes */
    if (!sq_ctx->hard_lim)
        return 0;

    /* TODO: check these under lock */
    int64_t compare_size = sq_ctx->total_size +
                           GF_ATOMIC_GET(sq_ctx->pending_update);
    if (sq_ctx->hard_lim < compare_size)
        return EDQUOT;

    return 0;
}

static void *
quota_set_thread_proc(void *data)
{
    int ret = -1;
    xlator_t *this = NULL;
    sq_private_t *priv = NULL;
    uint32_t interval = 0;
    this = data;
    priv = this->private;

    /* FIXME: decide on the interval, provide option */
    interval = 5;
    gf_msg_debug(this->name, 0,
                 "disk-space thread started, "
                 "interval = %d seconds",
                 interval);
    while (1) {
        /* aborting sleep() is a request to exit this thread, sleep()
         * will normally not return when cancelled */
        ret = sleep(interval);
        if (ret > 0)
            break;
        sync_data_from_priv(this, priv);
    }

    gf_msg_debug(this->name, 0, "Quota Set thread exiting");

    return NULL;
}

/* FIXME: We should use timer instead */
int
quota_set_thread(xlator_t *xl)
{
    sq_private_t *priv = NULL;
    int ret = -1;

    priv = xl->private;

    ret = gf_thread_create(&priv->quota_set_thread, NULL, quota_set_thread_proc,
                           xl, "quotaset");
    if (ret) {
        gf_log(xl->name, GF_LOG_ERROR,
               "unable to setup disk space check thread");
    }
    return ret;
}

static int
sq_clear_thread(xlator_t *this, pthread_t thr_id)
{
    int ret = 0;
    void *retval = NULL;

    gf_log(this->name, GF_LOG_INFO, "clearing thread");
    /* send a cancel request to the thread */
    ret = pthread_cancel(thr_id);
    if (ret != 0) {
        gf_log(this->name, GF_LOG_ERROR, "pthread_cancel() failed %s",
               strerror(errno));
        goto out;
    }

    errno = 0;
    ret = pthread_join(thr_id, &retval);
    if ((ret != 0) || (retval != PTHREAD_CANCELED)) {
        gf_log(this->name, GF_LOG_ERROR, "pthread_join() failed %s",
               strerror(errno));
    }

out:
    return ret;
}

/* ====================================== */

int32_t
sq_writev_cbk(call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
              int32_t op_errno, struct iatt *prebuf, struct iatt *postbuf,
              dict_t *xdata)
{
    inode_t *namespace = frame->local;

    if (IS_SUCCESS(op_ret)) {
        sq_update_namespace(this, namespace, prebuf, postbuf, 0);
    }

    frame->local = NULL;
    inode_unref(namespace);
    STACK_UNWIND_STRICT(writev, frame, op_ret, op_errno, prebuf, postbuf,
                        xdata);
    return 0;
}

int32_t
sq_writev(call_frame_t *frame, xlator_t *this, fd_t *fd, struct iovec *vector,
          int32_t count, off_t offset, uint32_t flags, struct iobref *iobref,
          dict_t *xdata)
{
    size_t size = iov_length(vector, count);
    int32_t op_errno = sq_check_usage(this, fd->inode->ns_inode, size);

    if (op_errno)
        goto fail;

    frame->local = inode_ref(fd->inode->ns_inode);
    STACK_WIND(frame, sq_writev_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->writev, fd, vector, count, offset,
               flags, iobref, xdata);
    return 0;

fail:
    STACK_UNWIND_STRICT(writev, frame, -1, op_errno, NULL, NULL, NULL);
    return 0;
}

int32_t
sq_truncate_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                struct iatt *postbuf, dict_t *xdata)
{
    inode_t *namespace = frame->local;

    if (IS_SUCCESS(op_ret)) {
        sq_update_namespace(this, namespace, prebuf, postbuf, 0);
    }

    frame->local = NULL;
    inode_unref(namespace);
    STACK_UNWIND_STRICT(truncate, frame, op_ret, op_errno, prebuf, postbuf,
                        xdata);
    return 0;
}

int32_t
sq_truncate(call_frame_t *frame, xlator_t *this, loc_t *loc, off_t offset,
            dict_t *xdata)
{
    frame->local = inode_ref(loc->inode->ns_inode);
    STACK_WIND(frame, sq_truncate_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->truncate, loc, offset, xdata);
    return 0;
}

int32_t
sq_ftruncate_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                 struct iatt *postbuf, dict_t *xdata)
{
    inode_t *namespace = frame->local;

    if (IS_SUCCESS(op_ret)) {
        sq_update_namespace(this, namespace, prebuf, postbuf, 0);
    }

    frame->local = NULL;
    inode_unref(namespace);
    STACK_UNWIND_STRICT(ftruncate, frame, op_ret, op_errno, prebuf, postbuf,
                        xdata);
    return 0;
}

int32_t
sq_ftruncate(call_frame_t *frame, xlator_t *this, fd_t *fd, off_t offset,
             dict_t *xdata)
{
    frame->local = inode_ref(fd->inode->ns_inode);
    STACK_WIND(frame, sq_ftruncate_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->ftruncate, fd, offset, xdata);
    return 0;
}

int
sq_forget(xlator_t *this, inode_t *inode)
{
    sq_private_t *priv = this->private;
    sq_inode_t *sq_ctx;
    uint64_t tmp_mq = 0;

    inode_ctx_get(inode, this, &tmp_mq);
    if (!tmp_mq)
        return 0;
    sq_ctx = (sq_inode_t *)(uintptr_t)tmp_mq;
    LOCK(&priv->lock);
    {
        list_del_init(&sq_ctx->priv_list);
    }
    UNLOCK(&priv->lock);
    GF_FREE(sq_ctx);
    return 0;
}

int32_t
sq_statfs_cbk(call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
              int32_t op_errno, struct statvfs *buf, dict_t *xdata)
{
    inode_t *inode = NULL;
    uint64_t value = 0;
    int64_t usage = -1;
    int64_t avail = -1;
    int64_t blocks = 0;
    sq_inode_t *ctx = NULL;
    int64_t used = 0;

    inode = frame->local;

    /* This fop will fail mostly in case of client disconnect,
     * which is already logged. Hence, not logging here */
    if (IS_ERROR(op_ret))
        goto unwind;

    /*
     * We should never get here unless quota_statfs (below) sent us a
     * cookie, and it would only do so if the value was non-NULL.  This
     * check is therefore just routine defensive coding.
     */

    GF_VALIDATE_OR_GOTO("mq", inode, unwind);

    inode_ctx_get(inode, this, &value);
    ctx = (sq_inode_t *)(unsigned long)value;
    if (!ctx || ctx->hard_lim <= 0) {
        goto unwind;
    }

    /* This step is crucial for a proper sync of xattr at right intervals */
    used = ctx->xattr_size + GF_ATOMIC_GET(ctx->pending_update);

    { /* statfs is adjusted in this code block */
        usage = (used) / buf->f_bsize;

        blocks = (ctx->hard_lim / buf->f_bsize) + 1;
        buf->f_blocks = blocks;

        avail = buf->f_blocks - usage;
        avail = max(avail, 0);

        buf->f_bfree = avail;
        /*
         * We have to assume that the total assigned quota
         * won't cause us to dip into the reserved space,
         * because dealing with the overcommitted cases is
         * just too hairy (especially when different bricks
         * might be using different reserved percentages and
         * such).
         */
        buf->f_bavail = buf->f_bfree;
    }

    xdata = xdata ? dict_ref(xdata) : dict_new();

    int ret = dict_set_int32(xdata, "quota-deem-statfs", 1);
    if (!ret) {
        gf_log(this->name, GF_LOG_WARNING,
               "failed to set dict with 'deem-statfs'. Quota limits may not be "
               "properly displayed on client");
    }
unwind:
    if (inode)
        inode_unref(inode);

    frame->local = NULL;
    STACK_UNWIND_STRICT(statfs, frame, op_ret, op_errno, buf, xdata);

    if (xdata)
        dict_unref(xdata);
    return 0;
}

int32_t
sq_statfs(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata)
{
    frame->local = inode_ref(loc->inode->ns_inode);
    STACK_WIND(frame, sq_statfs_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->statfs, loc, xdata);
    return 0;
}

int32_t
sq_unlink_cbk(call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
              int32_t op_errno, struct iatt *preparent, struct iatt *postparent,
              dict_t *xdata)
{
    inode_t *namespace = frame->local;

    if (IS_SUCCESS(op_ret)) {
        int64_t blocks = 0;
        int ret = dict_get_int64(xdata, GF_GET_FILE_BLOCK_COUNT, &blocks);
        if (!ret) {
            gf_log(this->name, GF_LOG_DEBUG, "reduce size by %ld blocks",
                   blocks);
        }
        sq_update_namespace(this, namespace, preparent, postparent,
                            -(blocks * 512));
    }

    frame->local = NULL;
    inode_unref(namespace);
    STACK_UNWIND_STRICT(unlink, frame, op_ret, op_errno, preparent, postparent,
                        xdata);
    return 0;
}

int
sq_unlink(call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t xflag,
          dict_t *xdata)
{
    /* Get the ns inode from parent, it won't cause any changes */
    xdata = xdata ? dict_ref(xdata) : dict_new();
    if (!xdata)
        goto wind;
    int ret = dict_set_int64(xdata, GF_GET_FILE_BLOCK_COUNT, 0);
    if (ret)
        gf_log(this->name, GF_LOG_ERROR,
               "BUG: dict set failed (pargfid: %s, name: %s), "
               "still continuing",
               uuid_utoa(loc->pargfid), loc->name);

wind:
    frame->local = inode_ref(loc->parent->ns_inode);
    STACK_WIND(frame, sq_unlink_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->unlink, loc, xflag, xdata);
    if (xdata)
        dict_unref(xdata);
    return 0;
}

int32_t
sq_rmdir_cbk(call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
             int32_t op_errno, struct iatt *preparent, struct iatt *postparent,
             dict_t *xdata)
{
    inode_t *namespace = frame->local;

    if (IS_SUCCESS(op_ret)) {
        /* Just remove 1 block */
        sq_update_namespace(this, namespace, preparent, postparent, 4096);
    }

    frame->local = NULL;
    inode_unref(namespace);
    STACK_UNWIND_STRICT(unlink, frame, op_ret, op_errno, preparent, postparent,
                        xdata);
    return 0;
}

int
sq_rmdir(call_frame_t *frame, xlator_t *this, loc_t *loc, int flag,
         dict_t *xdata)
{
    frame->local = inode_ref(loc->parent->ns_inode);
    STACK_WIND(frame, sq_rmdir_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->rmdir, loc, flag, xdata);
    return 0;
}

int32_t
sq_lookup_cbk(call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
              int32_t op_errno, inode_t *cbk_inode, struct iatt *buf,
              dict_t *xdata, struct iatt *postparent)
{
    inode_t *inode = frame->local;
    if (!inode || !xdata)
        goto unwind;

    if (IS_ERROR(op_ret))
        goto unwind;

    int64_t limit = 0;
    int64_t size = 0;
    uint64_t val = 1;
    int ret = 0;

    ret = inode_ctx_set1(inode, this, &val);
    if (ret) {
        gf_log(this->name, GF_LOG_WARNING,
               "failed to set the flag in inode ctx");
    }

    /* If the Quota Limit is set on a non namespace dir, then this should be
     * ignored */

    if (!dict_get(xdata, GF_NAMESPACE_KEY))
        goto unwind;

    ret = dict_get_int64(xdata, SQUOTA_SIZE_KEY, &size);
    if (ret) {
        gf_log(this->name, GF_LOG_DEBUG, "quota size not set (%s), ignored",
               uuid_utoa(inode->gfid));
    }

    ret = dict_get_int64(xdata, SQUOTA_LIMIT_KEY, &limit);
    if (ret) {
        gf_log(this->name, GF_LOG_DEBUG,
               "quota limit not set on namespace (%s), ignored",
               uuid_utoa(inode->gfid));
    }

    sq_update_hard_limit(this, inode, limit, size);

unwind:
    if (inode)
        inode_unref(inode);

    frame->local = NULL;

    STACK_UNWIND_STRICT(lookup, frame, op_ret, op_errno, cbk_inode, buf, xdata,
                        postparent);
    return 0;
}

int32_t
sq_lookup(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata)
{
    /* Only in 1 time in lookup for a directory, send namespace and quota xattr
     */
    xdata = xdata ? dict_ref(xdata) : dict_new();
    if (!xdata)
        goto wind;

    if (IATT_TYPE_VALID(loc->inode->ia_type) &&
        !IA_ISDIR(loc->inode->ia_type)) {
        goto wind;
    }

    /* Only proceed on namespace inode */
    /*
    if (loc->inode->ns_inode != loc->inode) {
      goto wind;
    }
    */
    /* If we have validated the directory inode, good to ignore this */
    uint64_t val = 0;
    int ret = inode_ctx_get1(loc->inode, this, &val);
    if (!ret) {
        goto wind;
    }

    /* namespace key would be set in server-protocol's resolve itself */
    ret = dict_set_int32(xdata, SQUOTA_LIMIT_KEY, 0);
    if (ret) {
        gf_log(this->name, GF_LOG_ERROR,
               "BUG: dict set failed (pargfid: %s, name: %s), "
               "still continuing",
               uuid_utoa(loc->pargfid), loc->name);
    }
    ret = dict_set_int32(xdata, SQUOTA_SIZE_KEY, 0);
    if (ret) {
        gf_log(this->name, GF_LOG_ERROR,
               "BUG: dict set (quota size key) failed (pargfid: %s, name: %s), "
               "still continuing",
               uuid_utoa(loc->pargfid), loc->name);
    }

    /* Assumption: 'namespace' key would be set in server protocol */
    frame->local = inode_ref(loc->inode);
wind:

    STACK_WIND(frame, sq_lookup_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->lookup, loc, xdata);

    if (xdata)
        dict_unref(xdata);
    return 0;
}

int32_t
sq_setxattr_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, dict_t *xdata)
{
    inode_t *inode = frame->local;
    if (!inode)
        goto unwind;

    if (IS_ERROR(op_ret)) {
        inode_unref(inode);
        goto unwind;
    }

    int64_t val = (int64_t)(unsigned long)cookie;
    uint64_t setval = 1;
    int ret = 0;
    sq_update_hard_limit(this, inode, val, 0);
    /* Setting this flag wouldn't bother lookup() call much */
    ret = inode_ctx_set1(inode, this, &setval);
    if (ret) {
        gf_log(this->name, GF_LOG_WARNING,
               "failed to set the flag in inode ctx");
    }

    inode_unref(inode);

unwind:
    frame->local = NULL;
    STACK_UNWIND_STRICT(setxattr, frame, op_ret, op_errno, xdata);
    return 0;
}

int32_t
sq_setxattr(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *dict,
            int32_t flags, dict_t *xdata)
{
    int ret = 0;
    int64_t val = 0;

    ret = dict_get_int64(dict, QUOTA_USAGE_KEY, &val);
    if (!ret) {
        /* if this operation is not sent on namespace, fail the operation */
        if (loc->inode != loc->inode->ns_inode) {
            goto err;
        }

        sq_update_total_usage(this, loc->inode, val);

        /* CHECK: xdata NULL ok here ? */
        STACK_UNWIND_STRICT(setxattr, frame, 0, 0, NULL);
        return 0;
    }

    ret = dict_get_int64(dict, SQUOTA_LIMIT_KEY, &val);
    if (ret)
        goto wind;

    /* if this operation is not sent on namespace, fail the operation */
    if (loc->inode != loc->inode->ns_inode)
        goto err;

    frame->local = inode_ref(loc->inode);

wind:
    STACK_WIND_COOKIE(frame, sq_setxattr_cbk, (void *)(uintptr_t)val,
                      FIRST_CHILD(this), FIRST_CHILD(this)->fops->setxattr, loc,
                      dict, flags, xdata);

    return 0;

err:
    STACK_UNWIND_STRICT(setxattr, frame, -1, EINVAL, xdata);
    return 0;
}

int32_t
init(xlator_t *this)
{
    sq_private_t *priv;

    if (!this->children || this->children->next) {
        gf_log("marker-quota", GF_LOG_ERROR,
               "FATAL: marker-quota should have exactly one child");
        return -1;
    }

    if (!this->parents) {
        gf_log(this->name, GF_LOG_WARNING, "dangling volume. check volfile ");
    }

    priv = GF_CALLOC(sizeof(sq_private_t), 1, 0);
    if (!priv)
        return -1;

    INIT_LIST_HEAD(&priv->ns_list);
    LOCK_INIT(&priv->lock);
    this->private = priv;
    // quota_set_thread(this);

    gf_log(this->name, GF_LOG_INFO, "Marker Quota xlator loaded");
    return 0;
}

void
fini(xlator_t *this)
{
    sq_private_t *priv = this->private;

    if (!priv)
        return;
    // sq_clear_thread(this, priv->quota_set_thread);
    gf_log(this->name, GF_LOG_INFO, "calling fini");
    this->private = NULL;
    GF_FREE(priv);

    return;
}

int
notify(xlator_t *this, int32_t event, void *data, ...)
{
    /* FIXME: for future, handle brick-mux */
    if (GF_EVENT_PARENT_DOWN == event) {
        gf_log(this->name, GF_LOG_INFO,
               "trying to send all pending information");
        /* FIXME: as of now, fini()/notify() are not called and a bug #1749 is
           raised for the same. Once thats fixed this feature works fine */
        sync_data_from_priv(this, this->private);
    }

    gf_log(this->name, GF_LOG_INFO, "Test: Got %d", event);
    return default_notify(this, event, data);
}

struct xlator_fops fops = {
    .lookup = sq_lookup,
    .statfs = sq_statfs,
    .truncate = sq_truncate,
    .ftruncate = sq_ftruncate,
    .unlink = sq_unlink,
    .setxattr = sq_setxattr,
    .writev = sq_writev,
};

struct xlator_cbks cbks = {
    .forget = sq_forget,
};

struct volume_options options[] = {
    {.key = {NULL}},
};

xlator_api_t xlator_api = {
    .init = init,
    .fini = fini,
    .op_version = {GD_OP_VERSION_9_0},
    .fops = &fops,
    .cbks = &cbks,
    .options = options,
    .notify = notify,
    .identifier = "simple-quota",
    .category = GF_EXPERIMENTAL,
};
