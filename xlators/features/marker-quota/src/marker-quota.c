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

#include "marker-quota.h"

#define GF_NAMESPACE_KEY "trusted.glusterfs.namespace"
#define QUOTA_USAGE_KEY "trusted.gfs.quota.total-usage"

static uint64_t
mq_set_ns_hardlimit(xlator_t *this, inode_t *inode, int64_t limit, int64_t size,
                    bool set_ns)
{
    mq_private_t *priv = this->private;
    mq_inode_t *mq_ctx;
    uint64_t tmp_mq = 0;
    int ret = -1;

    mq_ctx = GF_MALLOC(sizeof(mq_inode_t), gf_common_mt_char);
    if (!mq_ctx)
        goto out;
    INIT_LIST_HEAD(&mq_ctx->priv_list);
    mq_ctx->size = 0;
    mq_ctx->dirty = false;
    mq_ctx->hard_lim = limit;
    mq_ctx->used_size = size;

    if (set_ns)
        mq_ctx->ns = inode;

    tmp_mq = (uint64_t)(unsigned long)mq_ctx;
    ret = inode_ctx_put(inode, this, tmp_mq);
    if (ret < 0) {
        GF_FREE(mq_ctx);
        tmp_mq = 0;
        goto out;
    }
    LOCK(&priv->lock);
    {
        list_add_tail(&mq_ctx->priv_list, &priv->ns_list);
    }
    UNLOCK(&priv->lock);

    gf_log(this->name, GF_LOG_INFO, "hardlimit set on %s (%ld)",
           uuid_utoa(inode->gfid), limit);
out:
    return tmp_mq;
}

static void
mq_update_namespace(xlator_t *this, inode_t *ns, struct iatt *prebuf,
                    struct iatt *postbuf, int32_t op_ret)
{
    mq_private_t *priv = this->private;
    mq_inode_t *mq_ctx;
    uint64_t tmp_mq = 0;

    if (!ns)
        goto out;

    int ret = inode_ctx_get(ns, this, &tmp_mq);
    if (!tmp_mq) {
        /* FIXME: should we fall back to root ?? */
        if (ns != ns->table->root) {
            ret = inode_ctx_get(ns->table->root, this, &tmp_mq);
        }
    }

    if (!tmp_mq) {
        tmp_mq = mq_set_ns_hardlimit(this, ns, 0, 0, true);
        if (!tmp_mq)
            goto out;
    }

    mq_ctx = (mq_inode_t *)(uintptr_t)tmp_mq;

    if (ns != mq_ctx->ns) {
        mq_ctx->ns = ns; /* Set this, as it is possible to have linked a wrong
                            inode pointer in lookup */
        gf_log(this->name, GF_LOG_INFO, "entry ns different: %p", ns);
    }

    LOCK(&mq_ctx->ns->lock);
    {
        mq_ctx->size += op_ret;
        mq_ctx->used_size += op_ret;
        mq_ctx->dirty = true;
    }
    UNLOCK(&mq_ctx->ns->lock);

out:
    return;
}

static void
mq_update_ns_usage(xlator_t *this, inode_t *inode, int64_t val)
{
    mq_private_t *priv = this->private;
    mq_inode_t *mq_ctx;
    uint64_t tmp_mq = 0;
    int64_t dirty_size = 0;
    int ret = inode_ctx_get(inode, this, &tmp_mq);
    if (!tmp_mq) {
        tmp_mq = mq_set_ns_hardlimit(this, inode, 0, val, true);
        if (!tmp_mq)
            goto out;
    } else {
        gf_log("usage update", GF_LOG_INFO, "%s %ld", uuid_utoa(inode->gfid), val);
        mq_ctx = (mq_inode_t *)(uintptr_t)tmp_mq;
        LOCK(&inode->lock);
        {
            dirty_size = mq_ctx->size;
            mq_ctx->used_size = val + dirty_size;
        }
        UNLOCK(&inode->lock);
    }

    if (dirty_size)
        gf_log(this->name, GF_LOG_INFO, "Found dirty_size %ld", dirty_size);
out:
    return;
}

static void
mq_update_hard_limit(xlator_t *this, inode_t *ns, int64_t limit, int64_t size)
{
    mq_private_t *priv = this->private;
    mq_inode_t *mq_ctx;
    uint64_t tmp_mq = 0;

    if (!ns)
        goto out;

    int ret = inode_ctx_get(ns, this, &tmp_mq);
    if (!tmp_mq) {
        tmp_mq = mq_set_ns_hardlimit(this, ns, limit, size,
                                     IATT_TYPE_VALID(ns->ia_type));
        if (!tmp_mq)
            goto out;
    } else {
        gf_log("hardlimit update", GF_LOG_INFO, "%s %ld %ld",
               uuid_utoa(ns->gfid), limit, size);
        mq_ctx = (mq_inode_t *)(uintptr_t)tmp_mq;
        mq_ctx->hard_lim = limit;
        mq_ctx->used_size = size;
    }

out:
    return;
}

static void *
quota_set_thread_proc(void *data)
{
    xlator_t *this = NULL;
    mq_private_t *priv = NULL;
    uint32_t interval = 0;
    int ret = -1;
    mq_inode_t *tmp;
    mq_inode_t *tmp2;
    int64_t size = 0;
    loc_t loc = {};
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

        if (list_empty(&priv->ns_list)) {
            continue;
        }
        /* TODO: the namespace inodes should flush thier sizes here */
        list_for_each_entry_safe(tmp, tmp2, &priv->ns_list, priv_list)
        {
            size = 0;
            if (!tmp->dirty || !tmp->ns) {
                tmp = NULL;
                continue;
            }
            LOCK(&tmp->ns->lock);
            {
                size = tmp->size;
                tmp->size = 0;
                tmp->dirty = false;
            }
            UNLOCK(&tmp->ns->lock);

            gf_log(this->name, GF_LOG_TRACE, "%s: Writing size of %" PRId64,
                   uuid_utoa(tmp->ns->gfid), size);

            dict_t *dict = dict_new();
            if (!dict) {
                continue;
            }

            // int64_t value_on_disk = hton64(size);
            int64_t value_on_disk = size;
            ret = dict_set_int64(dict, QUOTA_SIZE_KEY, value_on_disk);
            if (ret < 0) {
                dict_unref(dict);
                continue;
            }

            /* Send the request to actual gfid */
            loc.inode = inode_ref(tmp->ns);
            /* As we are doing only operation from server side */
            ret = syncop_setxattr(FIRST_CHILD(this), &loc, dict, 0, NULL, NULL);
            inode_unref(tmp->ns);
            dict_unref(dict);
            if (ret < 0) {
                gf_log(this->name, GF_LOG_ERROR,
                       "%s: Quota value update failed",
                       uuid_utoa(tmp->ns->gfid));
            }

            tmp = NULL;
        }
    }

    gf_msg_debug(this->name, 0, "Quota Set thread exiting");

    return NULL;
}

/* FIXME: We should use timer instead */
int
quota_set_thread(xlator_t *xl)
{
    mq_private_t *priv = NULL;
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
mq_clear_thread(xlator_t *this, pthread_t thr_id)
{
    int ret = 0;
    void *retval = NULL;

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
mq_writev_cbk(call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
              int32_t op_errno, struct iatt *prebuf, struct iatt *postbuf,
              dict_t *xdata)
{
    inode_t *namespace = frame->local;

    if (IS_SUCCESS(op_ret)) {
        mq_update_namespace(this, namespace, prebuf, postbuf, op_ret);
    }

    frame->local = NULL;
    inode_unref(namespace);
    STACK_UNWIND_STRICT(writev, frame, op_ret, op_errno, prebuf, postbuf,
                        xdata);
    return 0;
}

int32_t
mq_writev(call_frame_t *frame, xlator_t *this, fd_t *fd, struct iovec *vector,
          int32_t count, off_t offset, uint32_t flags, struct iobref *iobref,
          dict_t *xdata)
{
    frame->local = inode_ref(fd->inode->ns_inode);
    STACK_WIND(frame, mq_writev_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->writev, fd, vector, count, offset,
               flags, iobref, xdata);
    return 0;
}

int32_t
mq_truncate_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                struct iatt *postbuf, dict_t *xdata)
{
    inode_t *namespace = frame->local;

    if (IS_SUCCESS(op_ret)) {
        mq_update_namespace(this, namespace, prebuf, postbuf, op_ret);
    }

    frame->local = NULL;
    inode_unref(namespace);
    STACK_UNWIND_STRICT(truncate, frame, op_ret, op_errno, prebuf, postbuf,
                        xdata);
    return 0;
}

int32_t
mq_truncate(call_frame_t *frame, xlator_t *this, loc_t *loc, off_t offset,
            dict_t *xdata)
{
    frame->local = inode_ref(loc->inode->ns_inode);
    STACK_WIND(frame, mq_truncate_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->truncate, loc, offset, xdata);
    return 0;
}

int
mq_forget(xlator_t *this, inode_t *inode)
{
    mq_private_t *priv = this->private;
    mq_inode_t *mq_ctx;
    uint64_t tmp_mq = 0;

    inode_ctx_get(inode, this, &tmp_mq);
    if (!tmp_mq)
        return 0;
    mq_ctx = (mq_inode_t *)(uintptr_t)tmp_mq;
    LOCK(&priv->lock);
    {
        list_del_init(&mq_ctx->priv_list);
    }
    UNLOCK(&priv->lock);
    GF_FREE(mq_ctx);
    return 0;
}

int32_t
mq_statfs_cbk(call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
              int32_t op_errno, struct statvfs *buf, dict_t *xdata)
{
    inode_t *inode = NULL;
    uint64_t value = 0;
    int64_t usage = -1;
    int64_t avail = -1;
    int64_t blocks = 0;
    mq_inode_t *ctx = NULL;
    int ret = 0;

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
    ctx = (mq_inode_t *)(unsigned long)value;
    if (!ctx || ctx->hard_lim <= 0) {
        /* If this namespace is not root inode, fall back to root inode once */
        if (inode != inode->table->root) {
            inode_ctx_get(inode->table->root, this, &value);
            ctx = (mq_inode_t *)(unsigned long)value;
            if (!ctx || ctx->hard_lim <= 0) {
                /* If this namespace is not root inode, fall back to root inode
                 * once */
                goto unwind;
            }
        } else {
            goto unwind;
        }
    }
    gf_log("", GF_LOG_INFO, "%ld %ld", ctx->hard_lim, ctx->used_size);

    { /* statfs is adjusted in this code block */
        usage = (ctx->used_size) / buf->f_bsize;

        blocks = ctx->hard_lim / buf->f_bsize;
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
    if (!xdata)
        goto unwind;

    ret = dict_set_int8(xdata, "quota-deem-statfs", 1);
    if (-1 == ret)
        gf_log(this->name, GF_LOG_ERROR,
               "Dict set failed, deem-statfs option may "
               "have no effect");
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
mq_statfs(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata)
{
    gf_log("", GF_LOG_INFO, "%s", loc->path);
    frame->local = inode_ref(loc->inode->ns_inode);
    STACK_WIND(frame, mq_statfs_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->statfs, loc, xdata);
    return 0;
}

int32_t
mq_unlink_cbk(call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
              int32_t op_errno, struct iatt *preparent, struct iatt *postparent,
              dict_t *xdata)
{
    STACK_UNWIND_STRICT(unlink, frame, op_ret, op_errno, preparent, postparent,
                        xdata);
    return 0;
}

int
mq_unlink(call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t xflag,
          dict_t *xdata)
{
    STACK_WIND(frame, mq_unlink_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->unlink, loc, xflag, xdata);
    return 0;
}

int32_t
mq_rmdir_cbk(call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
             int32_t op_errno, struct iatt *preparent, struct iatt *postparent,
             dict_t *xdata)
{
    STACK_UNWIND_STRICT(unlink, frame, op_ret, op_errno, preparent, postparent,
                        xdata);
    return 0;
}

int
mq_rmdir(call_frame_t *frame, xlator_t *this, loc_t *loc, int flag,
         dict_t *xdata)
{
    STACK_WIND(frame, mq_rmdir_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->rmdir, loc, flag, xdata);
    return 0;
}

int32_t
mq_lookup_cbk(call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
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

    gf_log("", GF_LOG_INFO, "1");
    ret = inode_ctx_set1(inode, this, &val);
    if (ret) {
        gf_log(this->name, GF_LOG_WARNING,
               "failed to set the flag in inode ctx");
    }
    /* If the Quota Limit is set on a non namespace dir, then this should be
     * ignored */

    gf_log("", GF_LOG_INFO, "2");
    ret = dict_get_int64(xdata, QUOTA_SIZE_KEY, &size);
    if (ret)
        goto unwind;

    gf_log("", GF_LOG_INFO, "3");
    ret = dict_get_int64(xdata, QUOTA_LIMIT_KEY, &limit);
    if (ret) {
        gf_log(this->name, GF_LOG_INFO,
               "quota limit not set on namespace (%s), ignored",
               uuid_utoa(inode->gfid));
    }

    gf_log("", GF_LOG_INFO, "limit: %ld, size: %ld", limit, size);
    mq_update_hard_limit(this, inode, limit, size);

unwind:
    if (inode)
        inode_unref(inode);

    frame->local = NULL;

    STACK_UNWIND_STRICT(lookup, frame, op_ret, op_errno, cbk_inode, buf, xdata,
                        postparent);
    return 0;
}

int32_t
mq_lookup(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata)
{
    /* Only in 1 time in lookup for a directory, send namespace and quota xattr
     */
    xdata = xdata ? dict_ref(xdata) : dict_new();
    if (!xdata)
        goto wind;

    if (IATT_TYPE_VALID(loc->inode->ia_type) &&
        !__is_root_gfid(loc->inode->gfid)) {
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
        gf_log("", GF_LOG_INFO, "%s %lu", loc->path, val);
        goto wind;
    }
    gf_log("", GF_LOG_INFO, "outside - %s", loc->path);

    /* namespace key would be set in server-protocol's resolve itself */
    ret = dict_set_int32(xdata, QUOTA_LIMIT_KEY, 1);
    if (ret) {
        gf_log(this->name, GF_LOG_ERROR,
               "BUG: dict set failed (pargfid: %s, name: %s), "
               "still continuing",
               uuid_utoa(loc->pargfid), loc->name);
    }
    ret = dict_set_int32(xdata, QUOTA_SIZE_KEY, 1);
    if (ret) {
        gf_log(this->name, GF_LOG_ERROR,
               "BUG: dict set failed (pargfid: %s, name: %s), "
               "still continuing",
               uuid_utoa(loc->pargfid), loc->name);
    }

    frame->local = inode_ref(loc->inode);
wind:

    STACK_WIND(frame, mq_lookup_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->lookup, loc, xdata);

    if (xdata)
        dict_unref(xdata);
    return 0;
}

int32_t
mq_setxattr_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
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
    mq_update_hard_limit(this, inode, val, 0);
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
mq_setxattr_usage_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
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
    mq_update_ns_usage(this, inode, val);

    inode_unref(inode);

unwind:
    frame->local = NULL;
    STACK_UNWIND_STRICT(setxattr, frame, op_ret, op_errno, xdata);
    return 0;
}

int32_t
mq_setxattr(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *dict,
            int32_t flags, dict_t *xdata)
{
    data_t *data = NULL;
    int op_errno = ENOMEM;
    int ret1 = 0;
    int ret2 = 0;
    int64_t val = 0;

    ret1 = dict_get_int64(dict, QUOTA_USAGE_KEY, &val);
    if (ret1) {
        ret2 = dict_get_int64(dict, QUOTA_LIMIT_KEY, &val);
    }

    if (ret1 && ret2)
        goto wind;

    /* if this operation is not sent on namespace, fail the operation */
    if (loc->inode != loc->inode->ns_inode)
        goto err;

    frame->local = inode_ref(loc->inode);

    if (!ret1)
        goto usage;

wind:
    STACK_WIND_COOKIE(frame, mq_setxattr_cbk, (void *)(uintptr_t)val,
                      FIRST_CHILD(this), FIRST_CHILD(this)->fops->setxattr, loc,
                      dict, flags, xdata);

    return 0;

usage:
    STACK_WIND_COOKIE(frame, mq_setxattr_usage_cbk, (void *)(uintptr_t)val,
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
    mq_private_t *priv;

    if (!this->children || this->children->next) {
        gf_log("marker-quota", GF_LOG_ERROR,
               "FATAL: marker-quota should have exactly one child");
        return -1;
    }

    if (!this->parents) {
        gf_log(this->name, GF_LOG_WARNING, "dangling volume. check volfile ");
    }

    priv = GF_CALLOC(sizeof(mq_private_t), 1, 0);
    if (!priv)
        return -1;

    INIT_LIST_HEAD(&priv->ns_list);
    LOCK_INIT(&priv->lock);
    this->private = priv;
    quota_set_thread(this);

    gf_log(this->name, GF_LOG_INFO, "Marker Quota xlator loaded");
    return 0;
}

void
fini(xlator_t *this)
{
    mq_private_t *priv = this->private;

    if (!priv)
        return;
    mq_clear_thread(this, priv->quota_set_thread);
    this->private = NULL;
    GF_FREE(priv);

    return;
}

int
notify(xlator_t *this, int32_t event, void *data, ...)
{
    /* FIXME: for future, handle brick-mux */
    if (GF_EVENT_PARENT_DOWN == event) {
        quota_set_thread_proc(this);
    }

    return default_notify(this, event, data);
}

struct xlator_fops fops = {
    .lookup = mq_lookup,
    .statfs = mq_statfs,
    .truncate = mq_truncate,
    .unlink = mq_unlink,
    .setxattr = mq_setxattr,
    .writev = mq_writev,
};

struct xlator_cbks cbks = {
    .forget = mq_forget,
};

struct volume_options options[] = {
    {.key = {NULL}},
};

xlator_api_t xlator_api = {
    .init = init,
    .fini = fini,
    .op_version = {1},
    .fops = &fops,
    .cbks = &cbks,
    .options = options,
    .notify = notify,
    .identifier = "marker-quota",
    .category = GF_EXPERIMENTAL,
};
