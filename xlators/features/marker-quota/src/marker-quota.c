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

#include "marker-quota.h"

#define QUOTA_LIMIT_KEY "trusted.glusterfs.quota-limit"
#define GF_NAMESPACE_KEY "trusted.glusterfs.namespace"

static int
mq_set_ns_hardlimit(xlator_t *this, inode_t *inode, uint64_t limit)
{
    mq_private_t *priv = this->private;
    mq_inode_t *mq_ctx;
    uint64_t tmp_mq;
    int ret = -1;

    mq_ctx = GF_MALLOC(sizeof(mq_inode_t), gf_common_mt_char);
    if (!mq_ctx)
        goto out;
    INIT_LIST_HEAD(&mq_ctx->priv_list);
    mq_ctx->size = 0;
    mq_ctx->hard_lim = limit;
    mq_ctx->dirty = false;

    mq_ctx->ns = inode;
    tmp_mq = (uint64_t)(unsigned long)mq_ctx;
    ret = inode_ctx_put(inode, this, tmp_mq);
    if (ret < 0) {
        GF_FREE(mq_ctx);
        goto out;
    }
    LOCK(&priv->lock);
    {
        list_add_tail(&mq_ctx->priv_list, &priv->ns_list);
    }
    UNLOCK(&priv->lock);

    gf_log(this->name, GF_LOG_INFO,
	   "hardlimit set on %s", uuid_utoa(inode->gfid));
    ret = 0;
out:
    return ret;
}

static void
mq_update_namespace(xlator_t *this, inode_t *ns, struct iatt *prebuf,
                    struct iatt *postbuf, int32_t op_ret)
{
    mq_private_t *priv = this->private;
    mq_inode_t *mq_ctx;
    uint64_t tmp_mq;

    if (!ns)
      goto out;

    int ret = inode_ctx_get(ns, this, &tmp_mq);
    if (!tmp_mq) {
        /* fall back to root */
      gf_log(this->name, GF_LOG_INFO,
	     "ctx value -- %ld", tmp_mq);
        if (ns != ns->table->root) {
            ret = inode_ctx_get(ns->table->root, this, &tmp_mq);
        }
    }

    if (!tmp_mq)
        goto out;
    
    mq_ctx = (mq_inode_t *)(uintptr_t)tmp_mq;

    gf_log(this->name, GF_LOG_INFO,
	   "ctx value %p", mq_ctx);
    
    if (ns != mq_ctx->ns) {
        mq_ctx->ns = ns; /* Set this, as it is possible to have linked a wrong                            inode pointer in lookup */
	gf_log(this->name, GF_LOG_INFO,
	       "entry ns different: %p", ns);
    }

    LOCK(&mq_ctx->ns->lock);
    {
        mq_ctx->size += op_ret;
        mq_ctx->dirty = true;
    }
    UNLOCK(&mq_ctx->ns->lock);

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
            if (tmp->dirty && tmp->ns) {
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
                ret = dict_set_static_bin(dict, QUOTA_SIZE_KEY, &value_on_disk,
                                          sizeof(int64_t *));
                if (ret < 0) {
                    dict_unref(dict);
                    continue;
                }

                /* Send the request to actual gfid */
                loc.inode = inode_ref(tmp->ns);
                ret = syncop_xattrop(FIRST_CHILD(this), &loc,
                                     GF_XATTROP_ADD_ARRAY64, dict, NULL, NULL,
                                     NULL);
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
    uint64_t tmp_mq;

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
    if (op_ret == -1)
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

    { /* statfs is adjusted in this code block */
        usage = (ctx->size) / buf->f_bsize;

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
              int32_t op_errno, inode_t *inode, struct iatt *buf, dict_t *xdata,
              struct iatt *postparent)
{
    if (!frame->local || !xdata)
        goto unwind;

    if (IS_ERROR(op_ret))
        goto unwind;

    /* If the Quota Limit is set on a non namespace dir, then this should be
     * ignored */
    if (!dict_get(xdata, GF_NAMESPACE_KEY))
        goto unwind;

    int64_t val = 0;
    int ret = dict_get_int64(xdata, QUOTA_LIMIT_KEY, &val);
    if (!val)
        goto unwind;

    ret = mq_set_ns_hardlimit(this, inode, val);
    if (ret)
        goto unwind;

unwind:
    gf_log("", GF_LOG_INFO, "Already set looked up inode %p", frame->local);
    frame->local = NULL;

    STACK_UNWIND_STRICT(lookup, frame, op_ret, op_errno, inode, buf, xdata,
                        postparent);
    return 0;
}

int32_t
mq_lookup(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata)
{
    /* Only in fresh lookup, send namespace and quota xattr */
    if (IATT_TYPE_VALID(loc->inode->ia_type)) {
      gf_log("", GF_LOG_INFO, "Already set looked up inode %d", loc->inode->ia_type);
        goto wind;
    }

    xdata = xdata ? dict_ref(xdata) : dict_new();
    if (!xdata)
        goto wind;

    /* namespace key would be set in server-protocol's resolve itself */
    int ret = dict_set_int32(xdata, QUOTA_LIMIT_KEY, 1);
    if (ret) {
        gf_log(this->name, GF_LOG_ERROR,
               "BUG: dict set failed (pargfid: %s, name: %s), "
               "still continuing",
               uuid_utoa(loc->pargfid), loc->name);
    }

    frame->local = (void *)42; /* just a value, which is not 0 */

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
    int ret = mq_set_ns_hardlimit(this, inode, val);
    inode_unref(inode);
    if (ret)
        goto unwind;

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
    int ret = 0;
    int64_t val = 0;

    ret = dict_get_int64(dict, QUOTA_LIMIT_KEY, &val);
    if (!val)
        goto wind;

    /* if this operation is not sent on namespace, fail the operation */
    if (loc->inode != loc->inode->ns_inode)
        goto err;

    frame->local = inode_ref(loc->inode);

wind:
    STACK_WIND_COOKIE(frame, mq_setxattr_cbk, (void *)(uintptr_t)val,
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
    this->private = NULL;
    GF_FREE(priv);

    return;
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
    .identifier = "marker-quota",
    .category = GF_EXPERIMENTAL,
};
