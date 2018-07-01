/*
   Copyright (c) 2006-2018 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#include "rwo-client.h"

/* FOP section */
int
rwoc_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno,
                 inode_t *inode, struct iatt *buf,
                 dict_t *xdata, struct iatt *postparent)
{
        int ret = 0;
        uint64_t open_count = 0;
        if (op_ret > 0) {
                ret = dict_get_uint64 (xdata, "trusted.glusterfs.open_gen_count",
                                       &open_count);
                if (ret == -1)
                        gf_msg_debug (this->name, ENOMEM,
                                      "failed to set dict");
                ret = inode_ctx_set0 (inode, this, &open_count);
                if (ret == -1)
                        gf_msg_debug (this->name, ENOMEM,
                                      "failed to set inode ctx");
        }

        STACK_UNWIND_STRICT (lookup, frame, op_ret, op_errno, inode, buf,
                             xdata, postparent);
        return 0;
}

int
rwoc_lookup (call_frame_t *frame, xlator_t *this,
             loc_t *loc, dict_t *xdata)
{
        int ret = 0;

        if (!xdata)
                xdata = dict_new ();
        else
                dict_ref (xdata);

        ret = dict_set_uint64 (xdata, "trusted.glusterfs.open_gen_count", 0);
        if (ret == -1)
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM, RWOC_MSG_NO_MEMORY,
                        "failed to set dict");

        STACK_WIND (frame, rwoc_lookup_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->lookup, loc, xdata);

        return 0;
}

int
rwoc_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, fd_t *fd, dict_t *xdata)
{
        STACK_UNWIND_STRICT (open, frame, op_ret, op_errno, fd, xdata);
        return 0;
}

int
rwoc_open (call_frame_t *frame, xlator_t *this, loc_t *loc,
           int32_t flags, fd_t *fd, dict_t *xdata)
{
        int ret = 0;
        uint64_t open_count = 0;

        ret = inode_ctx_get (loc->inode, this, &open_count);
        if (ret == -1)
                gf_msg_debug (this->name, ENODATA,
                              "failed to get data from inode_ctx");

        ret = dict_set_uint64 (xdata, "trusted.glusterfs.open_gen_count",
                               open_count);
        if (ret == -1)
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM, RWOC_MSG_NO_MEMORY,
                        "failed to set dict");

        STACK_WIND (frame, rwoc_open_cbk,
                    FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->open,
                    loc, flags, fd, xdata);
        return 0;
}

int
rwoc_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, fd_t *fd, inode_t *inode,
                 struct iatt *buf, struct iatt *preparent,
                 struct iatt *postparent, dict_t *xdata)
{
        STACK_UNWIND_STRICT (create, frame, op_ret, op_errno, fd, inode, buf,
                             preparent, postparent, xdata);
        return 0;
}

int
rwoc_create (call_frame_t *frame, xlator_t *this,
             loc_t *loc, int32_t flags, mode_t mode,
             mode_t umask, fd_t *fd, dict_t *xdata)
{
        int ret = -1;

        ret = dict_set_uint64 (xdata, "trusted.glusterfs.open_gen_count", 0);
        if (ret == -1)
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM, RWOC_MSG_NO_MEMORY,
                        "failed to set dict");

        STACK_WIND (frame, rwoc_create_cbk,
                    FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->create,
                    loc, flags, mode, umask, fd, xdata);
        return 0;
}


/* End of FOP section */

int32_t
rwoc_mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        GF_VALIDATE_OR_GOTO ("rwoc", this, out);

        ret = xlator_mem_acct_init (this, gf_rwoc_mt_end + 1);

        if (ret != 0) {
                gf_msg (this->name, GF_LOG_ERROR, ENOMEM, RWOC_MSG_NO_MEMORY,
                        "Memory accounting init failed");
                return ret;
        }
out:
        return ret;
}

int32_t
rwoc_dump_metrics (xlator_t *this, int fd)
{
        rwoc_private_t *priv = NULL;

        priv = this->private;
        dprintf (fd, "%s.private.dummy %d\n", this->name, priv->dummy);

        return 0;
}

int32_t
rwoc_init (xlator_t *this)
{
        int ret = -1;
        rwoc_private_t *priv = NULL;

        if (!this->children || this->children->next) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL, RWOC_MSG_NO_GRAPH,
                        "not configured with exactly one child. exiting");
                goto out;
        }

        if (!this->parents) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL, RWOC_MSG_NO_GRAPH,
                        "dangling volume. check volfile ");
                goto out;
        }

        priv = GF_CALLOC (1, sizeof (rwoc_private_t),
                          gf_rwoc_mt_private_t);

        GF_OPTION_INIT ("dummy", priv->dummy, int32, out);

        this->private = priv;
        ret = 0;

out:
        return ret;
}

int
rwoc_reconfigure (xlator_t *this, dict_t *options)
{
        int ret = -1;
        rwoc_private_t *priv = NULL;

        priv = this->private;

        GF_OPTION_RECONF ("dummy", priv->dummy, options, int32, out);

        ret = 0;
 out:
        return ret;
}

void
rwoc_fini (xlator_t *this)
{
        rwoc_private_t *priv = NULL;

        priv = this->private;
        this->private = NULL;

        GF_FREE (priv);
}

int
rwoc_notify (xlator_t *this, int32_t event, void *data, ...)
{
        switch (event) {
        default:
                default_notify (this, event, data);
                gf_msg_debug (this->name, 0, "event %d received", event);
        }

        return 0;
}

struct xlator_fops rwoc_fops = {
        .open = rwoc_open,
        .create = rwoc_create,
        .lookup = rwoc_lookup,
};

struct xlator_cbks rwoc_cbks = {
};

struct xlator_dumpops rwoc_dumpops = {
};

struct volume_options rwoc_options[] = {
        { .key   = {"dummy"},
          .type  = GF_OPTION_TYPE_INT,
          .min   = 1,
          .max   = 1024,
          .default_value = "1",
          .description = "a dummy option to show how to set the option",
          .op_version = {GD_OP_VERSION_4_2_0},
          .flags = OPT_FLAG_SETTABLE | OPT_FLAG_DOC,
          .level = OPT_STATUS_EXPERIMENTAL,
          .tags = { "development", "experimental", "rwoc" },
        },
        { .key  = {NULL} },
};


xlator_api_t xlator_api = {
        .init          = rwoc_init,
        .fini          = rwoc_fini,
        .notify        = rwoc_notify,
        .reconfigure   = rwoc_reconfigure,
        .mem_acct_init = rwoc_mem_acct_init,
        .dump_metrics  = rwoc_dump_metrics,
        .op_version    = {GD_OP_VERSION_4_2_0},
        .dumpops       = &rwoc_dumpops,
        .fops          = &rwoc_fops,
        .cbks          = &rwoc_cbks,
        .options       = rwoc_options,
        .identifier    = "rwoc",
};
