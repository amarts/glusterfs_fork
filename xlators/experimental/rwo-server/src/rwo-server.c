/*
   Copyright (c) 2006-2018 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#include "rwo-server.h"

/* FOPs section */
int
rwos_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
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
                                      "failed to get dict");
                /* Can happen if the create doesn't happen through
                   the newer version */
                if (open_count == 0)
                        open_count++;

                ret = inode_ctx_set0 (inode, this, &open_count);
                if (ret == -1)
                        gf_msg_debug (this->name, ENOMEM,
                                      "failed to set inode ctx");
                ret = dict_set_uint64 (xdata, "trusted.glusterfs.open_gen_count",
                                       open_count);
                if (ret == -1)
                        gf_msg_debug (this->name, ENOMEM,
                                      "failed to set dict");
        }

        STACK_UNWIND_STRICT (lookup, frame, op_ret, op_errno, inode, buf,
                             xdata, postparent);
        return 0;
}

int
rwos_lookup (call_frame_t *frame, xlator_t *this,
             loc_t *loc, dict_t *xdata)
{
        STACK_WIND (frame, rwos_lookup_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->lookup, loc, xdata);

        return 0;
}

int
rwos_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, fd_t *fd, dict_t *xdata)
{
        int ret = 0;
        uint64_t open_count = 0;
        uint64_t in_use = 0;

        if (op_ret >= 0 && cookie) {
                /* ctx1 for setting 'in-use' */
                in_use = 1;
                ret = inode_ctx_set1 (fd->inode, this, &in_use);
                if (ret == -1)
                        gf_msg_debug (this->name, ENOMEM,
                                      "failed to set inode ctx");

                /* Is there a atomic way to increment the context ?*/
                ret = inode_ctx_get0 (fd->inode, this, &open_count);
                if (ret == -1)
                        gf_msg_debug (this->name, ENOMEM,
                                      "failed to get inode ctx");
                open_count++;
                ret = inode_ctx_set0 (fd->inode, this, &open_count);
                if (ret == -1)
                        gf_msg_debug (this->name, ENOMEM,
                                      "failed to set inode ctx");
        }

        STACK_UNWIND_STRICT (open, frame, op_ret, op_errno, fd, xdata);
        return 0;
}

int
rwos_open (call_frame_t *frame, xlator_t *this, loc_t *loc,
           int32_t flags, fd_t *fd, dict_t *xdata)
{
        int ret = 0;
        uint64_t open_count = 0;
        uint64_t clnt_open_count = 0;
        uint64_t in_use = 0;

        /* If ! internal frame */
        if ((flags & O_ACCMODE) == O_RDONLY)
                goto go_ahead_and_open;

        /* TODO: add more comments, and do elaborate testing */
        ret = inode_ctx_get1 (loc->inode, this, &in_use);
        if (ret == -1)
                gf_msg_debug (this->name, ENODATA,
                              "failed to get data from inode_ctx");
        if (in_use) {
                gf_msg (this->name, GF_LOG_WARNING, EBUSY, RWOS_MSG_NO_MEMORY,
                        "already in use by other client %lu", in_use);
                STACK_UNWIND_STRICT (open, frame, -1, EBUSY, fd, xdata);
                return 0;
        }

        /* Validate the generation number client sent */
        ret = inode_ctx_get0 (loc->inode, this, &open_count);
        if (ret == -1)
                gf_msg_debug (this->name, ENODATA,
                              "failed to get data from inode_ctx");

        ret = dict_get_uint64 (xdata, "trusted.glusterfs.open_gen_count",
                               &clnt_open_count);
        if (ret == -1)
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM, RWOS_MSG_NO_MEMORY,
                        "failed to set dict");

        if (clnt_open_count && (open_count != clnt_open_count)) {
                gf_msg (this->name, GF_LOG_WARNING, ESTALE, RWOS_MSG_NO_MEMORY,
                        "client has stale information about the file (%lu),"
                        " would be good to get a revalidate lookup (%lu)",
                        clnt_open_count, open_count);
                STACK_UNWIND_STRICT (open, frame, -1, ESTALE, fd, xdata);
                return 0;
        }

        ret = dict_set_uint64 (xdata, "trusted.glusterfs.open_gen_count",
                               ++open_count);
        if (ret == -1)
                gf_msg_debug (this->name, ENOMEM,
                              "failed to set data in xdata");

go_ahead_and_open:
        STACK_WIND_COOKIE (frame, rwos_open_cbk, open_count,
                           FIRST_CHILD(this),
                           FIRST_CHILD(this)->fops->open,
                           loc, flags, fd, xdata);
        return 0;
}

int
rwos_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, fd_t *fd, inode_t *inode,
                 struct iatt *buf, struct iatt *preparent,
                 struct iatt *postparent, dict_t *xdata)
{
        int ret = 0;
        uint64_t open_count = 0;
        uint64_t in_use = 0;

        if (op_ret >= 0) {
                /* Will the fd->inode be proper ? */
                /* ctx1 for setting 'in-use' */
                in_use = 1;
                ret = inode_ctx_set1 (fd->inode, this, &in_use);
                if (ret == -1)
                        gf_msg_debug (this->name, ENOMEM,
                                      "failed to set inode ctx");

                open_count = 1;
                ret = inode_ctx_set0 (fd->inode, this, &open_count);
                if (ret == -1)
                        gf_msg_debug (this->name, ENOMEM,
                                      "failed to set inode ctx");
        }

        STACK_UNWIND_STRICT (create, frame, op_ret, op_errno, fd, inode, buf,
                             preparent, postparent, xdata);
        return 0;
}

int
rwos_create (call_frame_t *frame, xlator_t *this,
             loc_t *loc, int32_t flags, mode_t mode,
             mode_t umask, fd_t *fd, dict_t *xdata)
{
        int ret = -1;

        ret = dict_set_uint64 (xdata, "trusted.glusterfs.open_gen_count", 1);
        if (ret == -1)
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM, RWOS_MSG_NO_MEMORY,
                        "failed to set dict");

        STACK_WIND (frame, rwos_create_cbk,
                    FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->create,
                    loc, flags, mode, umask, fd, xdata);
        return 0;
}

int
rwos_setxattr (call_frame_t *frame, xlator_t *this,
               loc_t *loc, dict_t *dict,
               int32_t flags, dict_t *xdata)
{
        uint64_t in_use = 0;
        int ret = 0;

        if (dict && dict_get (dict, "rwo-release"))
                goto clear_flag;

        STACK_WIND_TAIL (frame, FIRST_CHILD(this),
                         FIRST_CHILD(this)->fops->setxattr,
                         loc, dict, flags, xdata);

        return 0;

clear_flag:
        /* Clear the inode context */
        ret = inode_ctx_reset1 (loc->inode, this, &in_use);
        if (ret == -1)
                gf_msg_debug (this->name, ENOMEM,
                              "failed to delete inode ctx");

        STACK_UNWIND_STRICT (setxattr, frame, 0, 0, NULL);
        return 0;
}

/* End of FOPs */

int32_t
rwos_mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        GF_VALIDATE_OR_GOTO ("rwos", this, out);

        ret = xlator_mem_acct_init (this, gf_rwos_mt_end + 1);

        if (ret != 0) {
                gf_msg (this->name, GF_LOG_ERROR, ENOMEM, RWOS_MSG_NO_MEMORY,
                        "Memory accounting init failed");
                return ret;
        }
out:
        return ret;
}

int32_t
rwos_dump_metrics (xlator_t *this, int fd)
{
        rwos_private_t *priv = NULL;

        priv = this->private;
        dprintf (fd, "%s.private.dummy %d\n", this->name, priv->dummy);

        return 0;
}

int32_t
rwos_init (xlator_t *this)
{
        int ret = -1;
        rwos_private_t *priv = NULL;

        if (!this->children || this->children->next) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL, RWOS_MSG_NO_GRAPH,
                        "not configured with exactly one child. exiting");
                goto out;
        }

        if (!this->parents) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL, RWOS_MSG_NO_GRAPH,
                        "dangling volume. check volfile ");
                goto out;
        }

        priv = GF_CALLOC (1, sizeof (rwos_private_t),
                          gf_rwos_mt_private_t);

        GF_OPTION_INIT ("dummy", priv->dummy, int32, out);

        this->private = priv;
        ret = 0;

out:
        return ret;
}

int
rwos_reconfigure (xlator_t *this, dict_t *options)
{
        int ret = -1;
        rwos_private_t *priv = NULL;

        priv = this->private;

        GF_OPTION_RECONF ("dummy", priv->dummy, options, int32, out);

        ret = 0;
 out:
        return ret;
}

void
rwos_fini (xlator_t *this)
{
        rwos_private_t *priv = NULL;

        priv = this->private;
        this->private = NULL;

        GF_FREE (priv);
}

int
rwos_notify (xlator_t *this, int32_t event, void *data, ...)
{
        switch (event) {
        default:
                default_notify (this, event, data);
                gf_msg_debug (this->name, 0, "event %d received", event);
        }

        return 0;
}

struct xlator_fops rwos_fops = {
        .open = rwos_open,
        .create = rwos_create,
        .lookup = rwos_lookup,
        .setxattr = rwos_setxattr,
};

struct xlator_cbks rwos_cbks = {
};

struct xlator_dumpops rwos_dumpops = {
};

struct volume_options rwos_options[] = {
        { .key   = {"dummy"},
          .type  = GF_OPTION_TYPE_INT,
          .min   = 1,
          .max   = 1024,
          .default_value = "1",
          .description = "a dummy option to show how to set the option",
          .op_version = {GD_OP_VERSION_4_2_0},
          .flags = OPT_FLAG_SETTABLE | OPT_FLAG_DOC,
          .level = OPT_STATUS_EXPERIMENTAL,
          .tags = { "development", "experimental", "rwos" },
        },
        { .key  = {NULL} },
};


xlator_api_t xlator_api = {
        .init          = rwos_init,
        .fini          = rwos_fini,
        .notify        = rwos_notify,
        .reconfigure   = rwos_reconfigure,
        .mem_acct_init = rwos_mem_acct_init,
        .dump_metrics  = rwos_dump_metrics,
        .op_version    = {GD_OP_VERSION_4_2_0},
        .dumpops       = &rwos_dumpops,
        .fops          = &rwos_fops,
        .cbks          = &rwos_cbks,
        .options       = rwos_options,
        .identifier    = "rwos",
};
