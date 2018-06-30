/*
   Copyright (c) 2006-2018 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#include "rwo-client.h"

int32_t
rwoc_mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        GF_VALIDATE_OR_GOTO ("rwoc", this, out);

        ret = xlator_mem_acct_init (this, gf_rwoc_mt_end + 1);

        if (ret != 0) {
                gf_msg (this->name, GF_LOG_ERROR, ENOMEM, TEMPLATE_MSG_NO_MEMORY,
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
                gf_msg (this->name, GF_LOG_ERROR, EINVAL, TEMPLATE_MSG_NO_GRAPH,
                        "not configured with exactly one child. exiting");
                goto out;
        }

        if (!this->parents) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL, TEMPLATE_MSG_NO_GRAPH,
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
