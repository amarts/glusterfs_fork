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

#include "marker-quota.h"

static void
mq_update_namespace(xlator_t *this, inode_t *ns, struct iatt *prebuf, struct iatt *postbuf, int32_t op_ret)
{
  mq_inode_t *mq_ctx = NULL;
  uint64_t tmp_mq;
  int64_t size = 0;
  int ret = inode_ctx_get(ns, this, &tmp_mq);
  if (!tmp_mq) {
    gf_log("", GF_LOG_INFO, "Here when no context");
    mq_ctx = GF_MALLOC(sizeof(mq_inode_t), gf_common_mt_char);
    if (!mq_ctx)
      goto out;
    mq_ctx->size = 0;
    tmp_mq = (uint64_t)(unsigned long)mq_ctx;
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
    size = mq_ctx->size;
    
  }
  UNLOCK(&ns->lock);

 out:
  gf_log("", GF_LOG_INFO, "Size is %"PRId64, size);
}

int32_t
mq_writev_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	      int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
	      struct iatt *postbuf, dict_t *xdata)
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
mq_writev(call_frame_t *frame, xlator_t *this, fd_t *fd,
             struct iovec *vector, int32_t count, off_t offset, uint32_t flags,
             struct iobref *iobref, dict_t *xdata)
{
    frame->local = inode_ref(fd->inode->ns_inode);
    STACK_WIND(frame, mq_writev_cbk, FIRST_CHILD(this),
               FIRST_CHILD(this)->fops->writev, fd, vector, count, offset,
               flags, iobref, xdata);
    return 0;
}

int32_t
init(xlator_t *this)
{
    mq_private_t *priv = this->private;

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

    this->private = priv;
    gf_log(this->name, GF_LOG_DEBUG, "Marker Quota xlator loaded");
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

struct xlator_fops fops = { .writev = mq_writev };

struct xlator_cbks cbks;

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
