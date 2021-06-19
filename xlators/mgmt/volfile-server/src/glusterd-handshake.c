/*
   Copyright (c) 2010-2012 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#include <glusterfs/xlator.h>
#include <glusterfs/defaults.h>
#include <glusterfs/glusterfs.h>
#include <glusterfs/syscall.h>
#include <glusterfs/compat-errno.h>

#include "glusterd.h"
#include "glusterd-utils.h"
#include "glusterd-op-sm.h"
#include "glusterd-store.h"
#include "glusterd-snapshot-utils.h"
#include "glusterd-svc-mgmt.h"
#include "glusterd-snapd-svc-helper.h"
#include "glusterd-volgen.h"
#include "glusterd-quotad-svc.h"
#include "glusterd-messages.h"
#include "glusterfs3.h"
#include "protocol-common.h"
#include "rpcsvc.h"
#include "rpc-common-xdr.h"
#include "glusterd-gfproxyd-svc-helper.h"
#include "glusterd-shd-svc-helper.h"


typedef ssize_t (*gfs_serialize_t)(struct iovec outmsg, void *data);

static int
get_snap_volname_and_volinfo(const char *volpath, char **volname,
                             glusterd_volinfo_t **volinfo)
{
    int ret = -1;
    char *save_ptr = NULL;
    char *str_token = NULL;
    char *snapname = NULL;
    char *volname_token = NULL;
    char *vol = NULL;
    glusterd_snap_t *snap = NULL;
    xlator_t *this = THIS;
    char *tmp_str_token = NULL;
    char *volfile_token = NULL;

    GF_ASSERT(volpath);
    GF_ASSERT(volinfo);

    str_token = gf_strdup(volpath);
    if (NULL == str_token) {
        goto out;
    }

    tmp_str_token = str_token;

    /* Input volname will have below formats:
     * /snaps/<snapname>/<volname>.<hostname>
     * or
     * /snaps/<snapname>/<parent-volname>
     * We need to extract snapname and parent_volname */

    /*split string by "/" */
    strtok_r(str_token, "/", &save_ptr);
    snapname = strtok_r(NULL, "/", &save_ptr);
    if (!snapname) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_INVALID_ENTRY,
               "Invalid path: %s", volpath);
        goto out;
    }

    volname_token = strtok_r(NULL, "/", &save_ptr);
    if (!volname_token) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_INVALID_ENTRY,
               "Invalid path: %s", volpath);
        goto out;
    }

    snap = glusterd_find_snap_by_name(snapname);
    if (!snap) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_NOT_FOUND,
               "Failed to "
               "fetch snap %s",
               snapname);
        goto out;
    }

    /* Find if its a parent volume name or snap volume
     * name. This function will succeed if volname_token
     * is a parent volname
     */
    ret = glusterd_volinfo_find(volname_token, volinfo);
    if (ret) {
        gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_VOLINFO_GET_FAIL,
               "failed to get the volinfo for the volume %s", volname_token);

        /* Get the actual volfile name. */
        volfile_token = strtok_r(NULL, "/", &save_ptr);
        *volname = gf_strdup(volfile_token);
        if (NULL == *volname) {
            gf_smsg(this->name, GF_LOG_ERROR, errno, GD_MSG_STRDUP_FAILED,
                    "Volname=%s", volfile_token, NULL);
            ret = -1;
            goto out;
        }

        /*
         * Ideally, this should succeed as volname_token now contains
         * the name of the snap volume (i.e. name of the volume that
         * represents the snapshot). But, if for some reason, volinfo
         * for the snap volume is not found, then try to get from the
         * name of the volfile. Name of the volfile is like this.
         * <snap volume name>.<hostname>.<brick path>.vol
         */
        ret = glusterd_snap_volinfo_find(volname_token, snap, volinfo);
        if (ret) {
            /* Split the volume name */
            vol = strtok_r(volfile_token, ".", &save_ptr);
            if (!vol) {
                gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_INVALID_ENTRY,
                       "Invalid "
                       "volname (%s)",
                       volfile_token);
                goto out;
            }

            ret = glusterd_snap_volinfo_find(vol, snap, volinfo);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_INFO_FAIL,
                       "Failed to "
                       "fetch snap volume from volname (%s)",
                       vol);
                goto out;
            }
        }
    } else {
        /*volname_token is parent volname*/
        ret = glusterd_snap_volinfo_find_from_parent_volname(volname_token,
                                                             snap, volinfo);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_INFO_FAIL,
                   "Failed to "
                   "fetch snap volume from parent "
                   "volname (%s)",
                   volname_token);
            goto out;
        }

        /* Since volname_token is a parent volname we should
         * get the snap volname here*/
        *volname = gf_strdup((*volinfo)->volname);
        if (NULL == *volname) {
            ret = -1;
            goto out;
        }
    }

out:
    if (ret && NULL != *volname) {
        GF_FREE(*volname);
        *volname = NULL;
    }

    if (tmp_str_token)
        GF_FREE(tmp_str_token);
    return ret;
}

int32_t
glusterd_get_client_per_brick_volfile(glusterd_volinfo_t *volinfo,
                                      char *filename, char *path, int path_len)
{
    glusterd_conf_t *priv = NULL;
    int32_t ret = -1;

    priv = THIS->private;
    GF_VALIDATE_OR_GOTO(THIS->name, priv, out);

    snprintf(path, path_len, "%s/%s", priv->workdir, filename);

    ret = 0;
out:
    return ret;
}

size_t
build_volfile_path(char *volume_id, char *path, size_t path_len)
{
    struct stat stbuf = {
        0,
    };
    int32_t ret = -1;
    char *volid_ptr = NULL;
    xlator_t *this = THIS;
    glusterd_conf_t *priv = NULL;

    priv = this->private;
    GF_ASSERT(priv);
    GF_ASSERT(volume_id);
    GF_ASSERT(path);

    if (volume_id[0] == '/') {
        /* Normal behavior */
        volid_ptr = volume_id;
        volid_ptr++;

    } else {
        /* Bringing in NFS like behavior for mount command, */
        /* With this, one can mount a volume with below cmd */
        /* bash# mount -t glusterfs server:/volume /mnt/pnt */
        volid_ptr = volume_id;
    }

gotvolinfo:
    ret = snprintf(path, path_len, "%s/%s.vol", priv->workdir, volid_ptr);
    if (ret == -1) {
        gf_smsg(this->name, GF_LOG_ERROR, errno, GD_MSG_COPY_FAIL, NULL);
        goto out;
    }

    ret = sys_stat(path, &stbuf);
out:
    return ret;
}


int
server_getspec(rpcsvc_request_t *req)
{
    int32_t ret = -1;
    int32_t op_ret = -1;
    int32_t op_errno = 0;
    int32_t spec_fd = -1;
    size_t file_len = 0;
    char filename[PATH_MAX] = {
        0,
    };
    struct stat stbuf = {
        0,
    };
    char *brick_name = NULL;
    char *volume = NULL;
    char *tmp = NULL;
    rpc_transport_t *trans = NULL;
    gf_getspec_req args = {
        0,
    };
    gf_getspec_rsp rsp = {
        0,
    };
    char addrstr[RPCSVC_PEER_STRLEN] = {0};
    peer_info_t *peerinfo = NULL;
    xlator_t *this = THIS;
    dict_t *dict = NULL;
    glusterd_peerinfo_t *peer = NULL;
    glusterd_conf_t *conf = NULL;
    int peer_cnt = 0;
    char *peer_hosts = NULL;
    char *tmp_str = NULL;
    char portstr[10] = {
        0,
    };
    int len = 0;

    conf = this->private;
    ret = xdr_to_generic(req->msg[0], &args, (xdrproc_t)xdr_gf_getspec_req);
    if (ret < 0) {
        // failed to decode msg;
        req->rpc_err = GARBAGE_ARGS;
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_REQ_DECODE_FAIL,
               "Failed to decode the message");
        goto fail;
    }

    peerinfo = &req->trans->peerinfo;

    volume = args.key;

    if (strlen(volume) >= (NAME_MAX)) {
        op_errno = EINVAL;
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_NAME_TOO_LONG,
               "volume name too long (%s)", volume);
        goto fail;
    }

    gf_msg(this->name, GF_LOG_INFO, 0, GD_MSG_MOUNT_REQ_RCVD,
           "Received mount request for volume %s", volume);

    /* Need to strip leading '/' from volnames. This was introduced to
     * support nfs style mount parameters for native gluster mount
     */

    ret = build_volfile_path(volume, filename, SLEN(filename));

    if (ret == 0) {
        /* to allocate the proper buffer to hold the file data */
        ret = sys_stat(filename, &stbuf);
        if (ret < 0) {
            gf_msg("glusterd", GF_LOG_ERROR, errno, GD_MSG_FILE_OP_FAILED,
                   "Unable to stat %s (%s)", filename, strerror(errno));
            goto fail;
        }

        spec_fd = open(filename, O_RDONLY);
        if (spec_fd < 0) {
            gf_msg("glusterd", GF_LOG_ERROR, errno, GD_MSG_FILE_OP_FAILED,
                   "Unable to open %s (%s)", filename, strerror(errno));
            goto fail;
        }
        ret = file_len = stbuf.st_size;
    }

    if (file_len) {
        rsp.spec = CALLOC(file_len + 1, sizeof(char));
        if (!rsp.spec) {
            gf_smsg(this->name, GF_LOG_ERROR, errno, GD_MSG_NO_MEMORY, NULL);
            ret = -1;
            op_errno = ENOMEM;
            goto fail;
        }
        ret = sys_read(spec_fd, rsp.spec, file_len);
    }

    /* convert to XDR */
fail:
    if (spec_fd >= 0)
        sys_close(spec_fd);

    rsp.op_ret = ret;
    if (rsp.op_ret < 0) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_MOUNT_REQ_FAIL,
               "Failed to mount the volume");
        if (!op_errno)
            op_errno = ENOENT;
    }

    if (op_errno)
        rsp.op_errno = gf_errno_to_error(op_errno);

    if (!rsp.spec)
        rsp.spec = strdup("");

    glusterd_submit_reply(req, &rsp, NULL, 0, NULL,
                          (xdrproc_t)xdr_gf_getspec_rsp);
    free(args.key);  // malloced by xdr
    free(rsp.spec);

    if (args.xdata.xdata_val)
        free(args.xdata.xdata_val);

    if (rsp.xdata.xdata_val)
        GF_FREE(rsp.xdata.xdata_val);

    return 0;
}


static rpcsvc_actor_t gluster_handshake_actors[GF_HNDSK_MAXVALUE] = {
    [GF_HNDSK_NULL] = {"NULL", NULL, NULL, GF_HNDSK_NULL, DRC_NA, 0},
    [GF_HNDSK_GETSPEC] = {"GETSPEC", server_getspec, NULL, GF_HNDSK_GETSPEC,
                          DRC_NA, 0},
};

struct rpcsvc_program gluster_handshake_prog = {
    .progname = "Gluster Handshake",
    .prognum = GLUSTER_HNDSK_PROGRAM,
    .progver = GLUSTER_HNDSK_VERSION,
    .actors = gluster_handshake_actors,
    .numactors = GF_HNDSK_MAXVALUE,
};

/* A minimal RPC program just for the cli getspec command */
static rpcsvc_actor_t gluster_cli_getspec_actors[GF_HNDSK_MAXVALUE] = {
    [GF_HNDSK_GETSPEC] = {"GETSPEC", server_getspec, NULL, GF_HNDSK_GETSPEC,
                          DRC_NA, 0},
};

struct rpcsvc_program gluster_cli_getspec_prog = {
    .progname = "Gluster Handshake (CLI Getspec)",
    .prognum = GLUSTER_HNDSK_PROGRAM,
    .progver = GLUSTER_HNDSK_VERSION,
    .actors = gluster_cli_getspec_actors,
    .numactors = GF_HNDSK_MAXVALUE,
};

static char *glusterd_dump_proc[GF_DUMP_MAXVALUE] = {
    [GF_DUMP_NULL] = "NULL",
    [GF_DUMP_DUMP] = "DUMP",
    [GF_DUMP_PING] = "PING",
};

static rpc_clnt_prog_t glusterd_dump_prog = {
    .progname = "GLUSTERD-DUMP",
    .prognum = GLUSTER_DUMP_PROGRAM,
    .progver = GLUSTER_DUMP_VERSION,
    .procnames = glusterd_dump_proc,
};
