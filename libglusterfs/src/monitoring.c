/*
  Copyright (c) 2017 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#include "monitoring.h"
#include "xlator.h"

#include <stdlib.h>


static void
update_latency_and_count (xlator_t *xl, int index, int fd)
{
        uint64_t fop;
        uint64_t cbk;
        char msg[1024] = {0,};
        glusterfs_graph_t *graph = NULL;

        graph = xl->graph;

        fop = GF_ATOMIC_GET (xl->metrics[index].fop);
        cbk = GF_ATOMIC_GET (xl->metrics[index].cbk);
        if (fop ) {
                snprintf (msg, sizeof(msg), "%s.%d.%s.count %lu\n",
                          xl->name, (graph)? graph->id:0, gf_fop_list[index], fop);
                write (fd, msg, strlen (msg));
        }
        if (cbk) {
                memset (msg, 0, sizeof (msg));
                snprintf (msg, sizeof(msg),
                          "%s.%d.%s.fail_count %lu\n",
                          xl->name, (graph)? graph->id:0, gf_fop_list[index],
                          cbk);
                write (fd, msg, strlen (msg));
        }
        if (xl->latencies[index].mean != 0.0) {
                memset (msg, 0, sizeof (msg));
                snprintf (msg, sizeof(msg), "%s.%d.%s.latency %lf\n",
                          xl->name, (graph)? graph->id:0, gf_fop_list[index],
                          xl->latencies[index].mean);
                write (fd, msg, strlen (msg));
        }
}

static void
dump_metrics (glusterfs_ctx_t *ctx, int fd)
{
        xlator_t *xl = NULL;
        glusterfs_graph_t *graph = NULL;
        int fop = 0;

        graph = ctx->active;
        xl = ctx->active->top;

        while (xl) {
                for (fop = 0; fop < GF_FOP_MAXVALUE; fop++) {
        
                        update_latency_and_count (xl, fop, fd);
                }
                xl = xl->next;
        }

        return;
}

void
gf_monitor_metrics (int sig, glusterfs_ctx_t *ctx)
{
        int fd = 0;
        char filepath[128] = {0,};

        strncat (filepath, "/tmp/glusterfsXXXXXX",
                 strlen ("/tmp/glusterfsXXXXXX"));
        fd = mkstemp (filepath);
        if (fd < 0) {
                gf_log ("signal", GF_LOG_ERROR,
                        "failed to open tmp file %s (%s)",
                        filepath, strerror (errno));
                /* GF_LOG */
                return;
        }

        gf_log ("Test", GF_LOG_ERROR, "success");
        dump_metrics (ctx, fd);
        close (fd);
out:
        return;
}
