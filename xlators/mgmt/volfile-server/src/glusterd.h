/*
   Copyright (c) 2006-2013 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef _GLUSTERD_H_
#define _GLUSTERD_H_

#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <libgen.h>

#include <glusterfs/compat-uuid.h>

#include "rpc-clnt.h"
#include <glusterfs/glusterfs.h>
#include <glusterfs/xlator.h>
#include <glusterfs/logging.h>
#include <glusterfs/call-stub.h>
#include <glusterfs/byte-order.h>
#include "glusterd-mem-types.h"
#include "rpcsvc.h"
#include "glusterd-sm.h"
#include "glusterd-snapd-svc.h"
#include "glusterd-shd-svc.h"
#include "glusterd-bitd-svc.h"
#include "glusterd1-xdr.h"
#include "protocol-common.h"
#include "glusterd-pmap.h"
#include "cli1-xdr.h"
#include <glusterfs/syncop.h>
#include <glusterfs/store.h>
#include <glusterfs/events.h>
#include "glusterd-gfproxyd-svc.h"

#include "gd-common-utils.h"


typedef struct {
    struct _volfile_ctx *volfile;
    pthread_mutex_t mutex;
    uuid_t uuid;
    rpcsvc_t *rpc;
    struct cds_list_head volumes;
    pthread_mutex_t xprt_lock;
    struct list_head xprt_list;
    gf_timer_t *timer;

    xlator_t *xl; /* Should be set to 'THIS' before creating thread */
    dict_t *opts;
    char workdir[VALID_GLUSTERD_PATHMAX];
} glusterd_conf_t;


#define GLUSTERD_DEFAULT_PORT GF_DEFAULT_BASE_PORT
#define GLUSTERD_VOLUME_DIR_PREFIX "vols"

#define GLUSTERD_GET_VOLUME_DIR(path, volinfo, priv)                           \
    do {                                                                       \
        int32_t _vol_dir_len;                                                  \
        if (volinfo->is_snap_volume) {                                         \
            _vol_dir_len = snprintf(                                           \
                path, PATH_MAX, "%s/snaps/%s/%s", priv->workdir,               \
                volinfo->snapshot->snapname, volinfo->volname);                \
        } else {                                                               \
            _vol_dir_len = snprintf(path, PATH_MAX, "%s/vols/%s",              \
                                    priv->workdir, volinfo->volname);          \
        }                                                                      \
        if ((_vol_dir_len < 0) || (_vol_dir_len >= PATH_MAX)) {                \
            path[0] = 0;                                                       \
        }                                                                      \
    } while (0)

int
glusterd_fetchspec_notify(xlator_t *this);


int
glusterd_rpc_create(struct rpc_clnt **rpc, dict_t *options,
                    rpc_clnt_notify_t notify_fn, void *notify_data,
                    gf_boolean_t force);


#endif
