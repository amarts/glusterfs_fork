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

static void
mq_update_namespace(xlator_t *this, inode_t *ns, struct iatt *prebuf,
                    struct iatt *postbuf, int32_t op_ret)
{
    mq_private_t *priv = this->private;
    mq_inode_t *mq_ctx;
    uint64_t tmp_mq;
    int ret = inode_ctx_get(ns, this, &tmp_mq);
    if (!tmp_mq) {
        mq_ctx = GF_MALLOC(sizeof(mq_inode_t), gf_common_mt_char);
        if (!mq_ctx)
            goto out;
        INIT_LIST_HEAD(&mq_ctx->priv_list);
        mq_ctx->size = 0;
        tmp_mq = (uint64_t)(unsigned long)mq_ctx;
        /* inode_ref() not required, as this keeps the ref of this inode only!
         */
        mq_ctx->ns = ns;
        LOCK(&priv->lock);
        {
            list_add_tail(&mq_ctx->priv_list, &priv->ns_list);
        }
        UNLOCK(&priv->lock);
        ret = inode_ctx_put(ns, this, tmp_mq);
        if (ret < 0) {
            GF_FREE(mq_ctx);
            goto out;
        }
    }

    mq_ctx = (mq_inode_t *)(uintptr_t)tmp_mq;

    LOCK(&ns->lock);
    {
        mq_ctx->size += op_ret;
        mq_ctx->dirty = true;
    }
    UNLOCK(&ns->lock);

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
                ret = dict_set_static_bin(dict, "trusted.glusterfs.consumption",
                                          &value_on_disk, sizeof(int64_t *));
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

struct xlator_fops fops = {.writev = mq_writev};

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
    .category = GF_MAINTAINED,
};
