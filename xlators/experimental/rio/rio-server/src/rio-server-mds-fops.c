/*
  Copyright (c) 2017 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

/* File: rio-server-mds-fops.c
 * This file contains the RIO MDC/server FOP entry and exit points.
 */

#include "xlator.h"
#include "call-stub.h"
#include "defaults.h"

#include "rio-common.h"
#include "rio-common-helpers.h"
#include "rio-server-mds-fops.h"
#include "layout.h"

/* Dirty inode refresh routines.
Dirty inodes are looked up in the DS (IOW, LOOKUP FOP is sent to the DS), and
the returned iatt information is ustilized as the latest inode information for
all fields that the DS is autoritative.

The following routines (2 currently), are the pair for sending the LOOKUP to the
DS and processing the return values, and updating the iatt stashed in the stub
of whichever FOP requested the refresh.

The intention is that this can be extended to other dirty iatt information
processing as required in the wind or the unwind paths. (for example pre/post
iatt information in certain FOPs).
*/
static int32_t
rio_refresh_iatt_from_ds_cbk (call_frame_t *frame, void *cookie,
                              xlator_t *this, int32_t op_ret, int32_t op_errno,
                              inode_t *inode, struct iatt *buf, dict_t *xdata,
                              struct iatt *postparent)
{
        struct rio_local *local = NULL;
        default_args_cbk_t *args;

        VALIDATE_OR_GOTO (frame, bailout);
        local = frame->local;
        VALIDATE_OR_GOTO (local, bailout);
        local->riolocal_iattrefreshed = _gf_true;
        args = &(local->riolocal_stub_cbk->args_cbk);
        VALIDATE_OR_GOTO (args, error);

        if (op_ret == 0) {
                /* Merge DS and MDS iatt to send back */
                /* NOTE: Merging is within the stashed stub data, so that stub
                resumes and such do not need any manupulation */
                rio_iatt_merge_mds_ds (&args->stat, buf);
        } else {
                errno = op_errno;
                goto error;
        }

        call_resume (local->riolocal_stub_cbk);
        return 0;
error:
        call_unwind_error (local->riolocal_stub_cbk, -1, errno);
bailout:
        return 0;
}

static void
rio_refresh_iatt_from_ds (call_frame_t *frame, xlator_t *this)
{
        struct rio_local *local = NULL;
        struct rio_conf *conf;
        loc_t inode_loc = {0,};
        inode_t *inode = NULL;
        default_args_cbk_t *args;
        xlator_t *subvol;

        VALIDATE_OR_GOTO (frame, bailout);
        local = frame->local;
        VALIDATE_OR_GOTO (local, bailout);
        args = &(local->riolocal_stub_cbk->args_cbk);
        VALIDATE_OR_GOTO (args, error);
        conf = local->riolocal_conf;
        VALIDATE_OR_GOTO (local, error);

        /* Find subvol to wind lookup to in DS */
        subvol = layout_search (conf->riocnf_dclayout,
                                local->riolocal_gfid);
        if (!subvol) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        RIO_MSG_LAYOUT_ERROR,
                        "Unable to find subvolume for GFID %s",
                        uuid_utoa (local->riolocal_gfid));
                errno = EINVAL;
                goto error;
        }

        /* TODO: Enhancement here would be to trust upcall post
        the first lookup of the inode, so that upcall can notify
        us of updates */

        if (local->riolocal_inode)
                inode = local->riolocal_inode;
        else
                inode = args->inode;

        rio_prepare_inode_loc (&inode_loc, inode, local->riolocal_gfid,
                               _gf_true);

        STACK_WIND (frame, rio_refresh_iatt_from_ds_cbk,
                    subvol, subvol->fops->lookup,
                    &inode_loc, NULL);
        loc_wipe (&inode_loc);
        return;
error:
        /* we attempted, and are erroring out, so OP is done */
        local->riolocal_iattrefreshed = _gf_true;
        call_unwind_error (local->riolocal_stub_cbk, -1, errno);
bailout:
        return;
}

/* TODO: This is wrapper functionality, we just turn right back till we have
utime xlator and POSIX changes to preserve size and time */
static int32_t
rio_cache_iatt_from_ds (call_frame_t *frame, xlator_t *this)
{
        struct rio_local *local = NULL;
        default_args_cbk_t *args;

        VALIDATE_OR_GOTO (frame, bailout);
        local = frame->local;
        VALIDATE_OR_GOTO (local, bailout);
        local->riolocal_iattrefreshed = _gf_true;
        args = &(local->riolocal_stub_cbk->args_cbk);
        VALIDATE_OR_GOTO (args, error);

        call_resume (local->riolocal_stub_cbk);
        return 0;
error:
        call_unwind_error (local->riolocal_stub_cbk, -1, errno);
bailout:
        return 0;
}

/* MDS LOOKUP Callback
If lookup returns an inode, the resolution is complete and we need the
checks as follows,
        - dirty inode handling
        - xaction handling
        - layout unlocking
If lookup returns EREMOTE, then only layout unlocking has to happen, as other
actions are done when we have the actual inode being processed.
*/
static int32_t
rio_server_mds_lookup_cbk (call_frame_t *frame, void *cookie,
                           xlator_t *this, int32_t op_ret, int32_t op_errno,
                           inode_t *inode, struct iatt *buf, dict_t *xdata,
                           struct iatt *postparent)
{
        struct rio_local *local = NULL;

        VALIDATE_OR_GOTO (frame, bailout);
        local = frame->local;
        VALIDATE_OR_GOTO (local, bailout);

        if (op_ret != 0) {
                goto done;
        }

        /* Dirty inode handling - for regular files only, nothing else has data
        in the DS */
        if (!(buf->ia_type & IA_IFREG)) {
                goto done;
        }

        /* Check if inode is dirty, or if we already refreshed a dirty inode */
        if (local->riolocal_iattrefreshed || !local->riolocal_idirty) {
                goto done;
        }

        /*** Dirty inode handling starts ***/
        /* stub the call back */
        local->riolocal_stub_cbk =
                fop_lookup_cbk_stub (frame, rio_server_mds_lookup_cbk, op_ret,
                                     op_errno, inode, buf, xdata, postparent);
        if (!local->riolocal_stub_cbk) {
                errno = ENOMEM;
                goto error;
        }

        /* Update GFID in local if lookup was not nameless to begin with */
        if (gf_uuid_is_null(local->riolocal_gfid)) {
                gf_uuid_copy (local->riolocal_gfid, buf->ia_gfid);
        }

        rio_refresh_iatt_from_ds (frame, this);
        return 0;
        /*** Dirty inode handling ends ***/

        /* TODO: xaction handling
        If inode is part of an ongoing xaction, we need saved/stored
        iatt information that we will respond with
                - inode->xactioninprogress
                - inode->savedlinkcount
        When we add this functionality, we would need a return function from
        the stub as well to handle these cases. */

        /* TODO: layout unlocks */

done:
        rio_local_wipe (local);
        STACK_UNWIND_STRICT (lookup, frame, op_ret, op_errno, inode, buf,
                             xdata, postparent);
        return 0;
error:
        rio_local_wipe (local);
        STACK_UNWIND (lookup, frame, -1, errno, NULL, NULL, NULL, NULL);
bailout:
        return 0;
}

/* LOOKUP Call
Lookup on MDS is passed directly to POSIX, which will return all information
or EREMOTE if inode is not local. Client handles EREMOTE resolution with the
correct MDS further.

Generic structure:
        - lock the layout
        - check if layout version is in agreement between client and MDS
        - mark the layout as in use (to prevent changes to the layout when
        FOPs are being processed)
        - Save inodes dirty state for a refresh
        - WIND to the next xlator
*/
int32_t
rio_server_mds_lookup (call_frame_t *frame, xlator_t *this, loc_t *loc,
                       dict_t *xdata)
{
        xlator_t *subvol;
        struct rio_conf *conf;
        struct rio_local *local = NULL;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);

        /* TODO: layout checks and locks */

        subvol = conf->riocnf_server_local_xlator;

        /* Create a local to store the lookup GFID */
        local = rio_local_init (frame, conf, NULL, NULL, NULL, GF_FOP_LOOKUP);
        if (!local) {
                errno = ENOMEM;
                goto error;
        }

        /* Save the GFID of the inode being looked up, if it is a nameless
        lookup */
        if (loc_is_nameless(loc)) {
                gf_uuid_copy (local->riolocal_gfid, loc->gfid);
        }

        /* If loc does not have an inode (no open fd's at this point), then it
        cannot be dirty, and if it does, then check if the inode is dirty or,
        just hanging around in the inode cache */
        if (loc->inode) {
                local->riolocal_idirty = rio_is_inode_dirty (loc->inode);
        } else {
                local->riolocal_idirty = _gf_false;
        }

        STACK_WIND (frame, rio_server_mds_lookup_cbk, subvol,
                    subvol->fops->lookup, loc, xdata);
        return 0;

error:
        STACK_UNWIND (lookup, frame, -1, errno, NULL, NULL, NULL, NULL);
bailout:
        return 0;
}

static int32_t
rio_server_mds_stat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                         int32_t op_ret, int32_t op_errno, struct iatt *buf,
                         dict_t *xdata)
{
        struct rio_local *local = NULL;

        VALIDATE_OR_GOTO (frame, bailout);
        local = frame->local;
        VALIDATE_OR_GOTO (local, bailout);

        if (op_ret != 0) {
                goto done;
        }

        /* Dirty inode handling - for regular files only, nothing else has data
        in the DS */
        if (!(buf->ia_type & IA_IFREG)) {
                goto done;
        }

        /* Check if inode is dirty, or if we already refreshed a dirty inode */
        if (local->riolocal_iattrefreshed || !local->riolocal_idirty) {
                goto done;
        }

        /*** Dirty inode handling starts ***/
        /* stub the call back */
        local->riolocal_stub_cbk =
                        fop_stat_cbk_stub (frame, rio_server_mds_stat_cbk,
                                           op_ret, op_errno, buf, xdata);
        if (!local->riolocal_stub_cbk) {
                errno = ENOMEM;
                goto error;
        }

        rio_refresh_iatt_from_ds (frame, this);
        return 0;
        /*** Dirty inode handling ends ***/

        /* TODO: xaction handling
        If inode is part of an ongoing xaction, we need saved/stored
        iatt information that we will respond with
                - inode->xactioninprogress
                - inode->savedlinkcount */

        /* TODO: layout unlocks */

done:
        if (local->riolocal_fop == GF_FOP_STAT)
                STACK_UNWIND_STRICT (stat, frame, op_ret, op_errno,
                                     buf, xdata);
        else
                STACK_UNWIND_STRICT (fstat, frame, op_ret, op_errno,
                                     buf, xdata);
        rio_local_wipe (local);
        return 0;
error:
        if (local->riolocal_fop == GF_FOP_STAT)
                STACK_UNWIND (stat, frame, -1, errno, NULL, NULL);
        else
                STACK_UNWIND (fstat, frame, -1, errno, NULL, NULL);
        rio_local_wipe (local);
bailout:
        return 0;
}

int32_t
rio_server_mds_stat (call_frame_t *frame, xlator_t *this, loc_t *loc,
                     dict_t *xdata)
{
        xlator_t *subvol;
        struct rio_conf *conf;
        struct rio_local *local = NULL;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);

        /* TODO: layout checks and locks */

        subvol = conf->riocnf_server_local_xlator;

        /* Save return values for future unwind */
        local = rio_local_init (frame, conf, NULL, NULL, NULL,
                                GF_FOP_STAT);
        if (!local) {
                errno = ENOMEM;
                goto error;
        }

        gf_uuid_copy (local->riolocal_gfid, loc->gfid);
        local->riolocal_inode = inode_ref (loc->inode);
        local->riolocal_idirty = rio_is_inode_dirty (loc->inode);

        STACK_WIND (frame, rio_server_mds_stat_cbk, subvol,
                    subvol->fops->stat, loc, xdata);
        return 0;

error:
        STACK_UNWIND (stat, frame, -1, errno, NULL, NULL);
bailout:
        return 0;
}

int32_t
rio_server_mds_fstat (call_frame_t *frame, xlator_t *this, fd_t *fd,
                      dict_t *xdata)
{
        xlator_t *subvol;
        struct rio_conf *conf;
        struct rio_local *local = NULL;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);

        /* TODO: layout checks and locks */

        subvol = conf->riocnf_server_local_xlator;

        /* Save return values for future unwind */
        local = rio_local_init (frame, conf, NULL, NULL, NULL,
                                GF_FOP_FSTAT);
        if (!local) {
                errno = ENOMEM;
                goto error;
        }

        gf_uuid_copy (local->riolocal_gfid, fd->inode->gfid);
        local->riolocal_inode = inode_ref (fd->inode);
        local->riolocal_idirty = rio_is_inode_dirty (fd->inode);

        STACK_WIND (frame, rio_server_mds_stat_cbk, subvol,
                    subvol->fops->fstat, fd, xdata);
        return 0;

error:
        STACK_UNWIND (fstat, frame, -1, errno, NULL, NULL);
bailout:
        return 0;
}

static int32_t
rio_server_setattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                        int32_t op_ret, int32_t op_errno,
                        struct iatt *preop_stbuf, struct iatt *postop_stbuf,
                        dict_t *xdata)
{
        struct rio_local *local = NULL;

        VALIDATE_OR_GOTO (frame, bailout);
        local = frame->local;
        VALIDATE_OR_GOTO (local, bailout);

        if (op_ret != 0) {
                goto done;
        }

        /* Dirty inode handling - for regular files only, nothing else has data
        in the DS */
        if (!(postop_stbuf->ia_type & IA_IFREG)) {
                goto done;
        }

        /* Check if inode is dirty, or if we already refreshed a dirty inode */
        if (local->riolocal_iattrefreshed || !local->riolocal_idirty) {
                goto done;
        }

        /*** Dirty inode handling starts ***/
        /* stub the call back */
        local->riolocal_stub_cbk =
                        fop_setattr_cbk_stub (frame, rio_server_setattr_cbk,
                                              op_ret, op_errno,
                                              preop_stbuf, postop_stbuf, xdata);
        if (!local->riolocal_stub_cbk) {
                errno = ENOMEM;
                goto error;
        }

        rio_refresh_iatt_from_ds (frame, this);
        return 0;
        /*** Dirty inode handling ends ***/

        /* TODO: xaction handling
        If inode is part of an ongoing xaction, we need saved/stored
        iatt information that we will respond with
                - inode->xactioninprogress
                - inode->savedlinkcount */

        /* TODO: layout unlocks */

done:
        if (local->riolocal_fop == GF_FOP_SETATTR)
                STACK_UNWIND_STRICT (setattr, frame, op_ret, op_errno,
                                     preop_stbuf, postop_stbuf, xdata);
        else
                STACK_UNWIND_STRICT (fsetattr, frame, op_ret, op_errno,
                                     preop_stbuf, postop_stbuf, xdata);
        rio_local_wipe (local);
        return 0;
error:
        if (local->riolocal_fop == GF_FOP_SETATTR)
                STACK_UNWIND (setattr, frame, -1, errno, NULL, NULL, NULL);
        else
                STACK_UNWIND (fsetattr, frame, -1, errno, NULL, NULL, NULL);
        rio_local_wipe (local);
bailout:
        return 0;
}

int32_t
rio_server_setattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                    struct iatt *stbuf, int32_t valid, dict_t *xdata)
{
        xlator_t *subvol;
        struct rio_conf *conf;
        struct rio_local *local = NULL;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);

        /* TODO: layout checks and locks */

        subvol = conf->riocnf_server_local_xlator;

        /* Save return values for future unwind */
        local = rio_local_init (frame, conf, NULL, NULL, NULL,
                                GF_FOP_SETATTR);
        if (!local) {
                errno = ENOMEM;
                goto error;
        }

        gf_uuid_copy (local->riolocal_gfid, loc->gfid);
        local->riolocal_inode = inode_ref (loc->inode);
        local->riolocal_idirty = rio_is_inode_dirty (loc->inode);

        STACK_WIND (frame, rio_server_setattr_cbk, subvol,
                    subvol->fops->setattr, loc, stbuf, valid, xdata);
        return 0;

error:
        STACK_UNWIND (setattr, frame, -1, errno, NULL, NULL, NULL);
bailout:
        return 0;
}

int32_t
rio_server_fsetattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
                     struct iatt *stbuf, int32_t valid, dict_t *xdata)
{
        xlator_t *subvol;
        struct rio_conf *conf;
        struct rio_local *local = NULL;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);

        /* TODO: layout checks and locks */

        subvol = conf->riocnf_server_local_xlator;

        /* Save return values for future unwind */
        local = rio_local_init (frame, conf, NULL, NULL, NULL,
                                GF_FOP_FSETATTR);
        if (!local) {
                errno = ENOMEM;
                goto error;
        }

        gf_uuid_copy (local->riolocal_gfid, fd->inode->gfid);
        local->riolocal_inode = inode_ref (fd->inode);
        local->riolocal_idirty = rio_is_inode_dirty (fd->inode);

        STACK_WIND (frame, rio_server_setattr_cbk, subvol,
                    subvol->fops->fsetattr, fd, stbuf, valid, xdata);
        return 0;

error:
        STACK_UNWIND (fsetattr, frame, -1, errno, NULL, NULL, NULL);
bailout:
        return 0;
}

static int32_t
rio_server_mds_truncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                             int32_t op_ret, int32_t op_errno,
                             struct iatt *prebuf, struct iatt *postbuf,
                             dict_t *xdata)
{
        struct rio_local *local = NULL;

        VALIDATE_OR_GOTO (frame, bailout);
        local = frame->local;
        VALIDATE_OR_GOTO (local, error);

        /* Check if inode cache is already refreshed */
        if (local->riolocal_iattrefreshed) {
                /* TODO: inode should be marked dirty no longer */
                goto done;
        }

        if (op_ret != 0) {
                /* TODO: Do errors still necessitate a cache refresh? */
                goto done;
        }

        /*** Dirty inode cache refresh starts ***/
        /* stub the call back */
        local->riolocal_stub_cbk =
                fop_truncate_cbk_stub (frame, rio_server_mds_truncate_cbk,
                                       op_ret, op_errno,
                                       prebuf, postbuf, xdata);
        if (!local->riolocal_stub_cbk) {
                errno = ENOMEM;
                goto error;
        }

        rio_cache_iatt_from_ds (frame, this);
        return 0;
        /*** Dirty inode cache refresh ends ***/

        /* TODO: xaction handling */
        /* TODO: layout unlocks */

done:
        STACK_UNWIND_STRICT (truncate, frame, op_ret, op_errno, prebuf, postbuf,
                             xdata);
        rio_local_wipe (local);
        return 0;
error:
        STACK_UNWIND (truncate, frame, -1, errno, NULL, NULL, NULL);
        rio_local_wipe (local);
bailout:
        return 0;
}

/* TRUNCATE Call
Truncate is passed to the DS, noting that the indoe is dirty in the interim,
and once the OP is completed at the DS, the inode cache is updated and response
returned to the callers.

Generic steps:
  - Determine which DS to send the operation to
  - Mark the inode dirty
  - Forward the operation to the DS
  - On, response, refresh local cache (if inode may become clean post truncate)
    - If we refresh the cache, then we get the pre/post iatt complete
  - Respond to the caller with the data
*/
int32_t
rio_server_mds_truncate (call_frame_t *frame, xlator_t *this, loc_t *loc,
                         off_t offset, dict_t *xdata)
{
        struct rio_local *local = NULL;
        struct rio_conf *conf;
        loc_t inode_loc = {0,};
        xlator_t *subvol;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);

        /* Find subvol to wind lookup to in DS */
        subvol = layout_search (conf->riocnf_dclayout, loc->gfid);
        if (!subvol) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        RIO_MSG_LAYOUT_ERROR,
                        "Unable to find subvolume for GFID %s",
                        uuid_utoa (loc->gfid));
                errno = EINVAL;
                goto error;
        }

        /* Save return values for future unwind */
        local = rio_local_init (frame, conf, NULL, NULL, NULL,
                                GF_FOP_FSETATTR);
        if (!local) {
                errno = ENOMEM;
                goto error;
        }

        /* TODO: Mark the inode as dirty, currently we treat all inodes as
        dirty */
        local->riolocal_inode = inode_ref (loc->inode);

        rio_prepare_inode_loc (&inode_loc, loc->inode, loc->gfid, _gf_true);

        STACK_WIND (frame, rio_server_mds_truncate_cbk,
                    subvol, subvol->fops->truncate,
                    &inode_loc, offset, xdata);
        loc_wipe (&inode_loc);
        return 0;
error:
        STACK_UNWIND (truncate, frame, -1, errno, NULL, NULL, NULL);
bailout:
        return 0;
}

static int32_t
rio_server_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                       int32_t op_ret, int32_t op_errno, fd_t *fd,
                       inode_t *inode, struct iatt *buf, struct iatt *preparent,
                       struct iatt *postparent, dict_t *xdata)
{
        VALIDATE_OR_GOTO (frame, bailout);

        /* on success, or unhandled failures, unwind */
        if (!op_ret || (op_ret != 0 && op_errno != EREMOTE)) {
                STACK_UNWIND (create, frame, op_ret, op_errno, fd, inode,
                              buf, preparent, postparent, xdata);
                return 0;
        }

        /* TODO: We need to handle the EREMOTE case, so for now the
         * unhandled part is just maintained as a special exception */
        /* (op_errno == EREMOTE)) */
        STACK_UNWIND (create, frame, op_ret, op_errno, fd, inode,
                      buf, preparent, postparent, xdata);
bailout:
        return 0;
}

/* CREATE Call
Create is passed to POSIX, and RIO does not fork the icreate and namelink
operations, as 2 FOP calls. POSIX may return EREMOTE, if the file already
exists, in which case create needs to further open the remote inode.

Generic structure:
        - generate a GFID that will colocate the file inode with the directory
        inode (same bucket #)
        - lock the layout
        - check if layout version is in agreement between client and MDS
        - mark the layout as in use (to prevent changes to the layout when
        FOPs are being processed)
        - WIND to the next xlator
*/
int32_t
rio_server_create (call_frame_t *frame, xlator_t *this, loc_t *loc,
                   int32_t flags, mode_t mode, mode_t umask, fd_t *fd,
                   dict_t *xdata)
{
        xlator_t *subvol;
        struct rio_conf *conf;
        uuid_t gfid_req;
        int ret;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);

        /* fill in gfid-req for entry creation, to colocate file inode with the
         * parent */
        /* TODO: Trust loc->pargfid in all cases? */
        layout_generate_colocated_gfid (conf->riocnf_mdclayout, gfid_req,
                                        loc->parent->gfid);

        /* TODO: gfid-req is something other parts of the code use as well. Need
         * to understand how this would work, when we overwrite the same with
         * our requested GFID */
        ret = dict_set_static_bin (xdata, "gfid-req", gfid_req, 16);
        if (ret) {
                errno = ENOMEM;
                goto error;
        }

        /* TODO: layout checks and locks */
        subvol = conf->riocnf_server_local_xlator;

        /* wind call to subvolume */
        STACK_WIND (frame, rio_server_create_cbk,
                    subvol, subvol->fops->create,
                    loc, flags, mode, umask, fd, xdata);

        return 0;
error:
        STACK_UNWIND (create, frame, -1, errno, NULL, NULL, NULL,
                      NULL, NULL, NULL);
bailout:
        return 0;
}

static int32_t
rio_server_mkdir_namelink_cbk (call_frame_t *frame, void *cookie,
                               xlator_t *this, int32_t op_ret,
                               int32_t op_errno, struct iatt *prebuf,
                               struct iatt *postbuf, dict_t *xdata)
{
        struct rio_local *local;

        VALIDATE_OR_GOTO (frame, bailout);
        local = frame->local;

        /* TODO: Orphan inode and journal */
        /* TODO: xdata should be merged from icreate and namelink and sent
        back? */
        STACK_UNWIND (mkdir, frame, op_ret, op_errno, local->riolocal_inode,
                      &local->riolocal_stbuf, prebuf, postbuf, xdata);
        rio_local_wipe (local);
        return 0;
bailout:
        return -1;
}

static int32_t
rio_server_mkdir_namelink (call_frame_t *frame, xlator_t *this,
                           struct rio_local *local)
{
        xlator_t *subvol;
        struct rio_conf *conf;

        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);

        /* TODO: layout checks and locks */
        subvol = conf->riocnf_server_local_xlator;

        /* TODO: namelink does not bother with umask? We need to for ACL
        checking to be right IMO. Further, umask should have been processed by
        the ACL, so that mode is adjusted appropriately. Needs further
        thought */
        STACK_WIND (frame, rio_server_mkdir_namelink_cbk, subvol,
                    subvol->fops->namelink, &local->riolocal_loc,
                    local->riolocal_xdata_in);
        return 0;
 error:
        rio_local_wipe (local);
        STACK_UNWIND (mkdir, frame, -1, errno, NULL, NULL, NULL, NULL, NULL);
        return -1;
}

/* ICREATE callback
icreate can be called only for mkdir (as of this writing). Hence this assumes
that this is a directory inode creation callback and acts accordingly.

Generic structure:
        - If creation failed, fail the FOP
        - Else, wind the namelink to the local MDS if we are the caller of
        mkdir
        - If we are not, then just unwind
*/
static int32_t
rio_server_icreate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                        int32_t op_ret, int32_t op_errno, inode_t *inode,
                        struct iatt *buf, dict_t *xdata)
{
        struct rio_local *local;
        glusterfs_fop_t infop;
        int32_t ret = 0;

        VALIDATE_OR_GOTO (frame, bailout);
        local = frame->local;
        /* Without infop cannot unwind correctly, hence bailout */
        VALIDATE_OR_GOTO (local, bailout);
        infop = local->riolocal_fop;
        VALIDATE_OR_GOTO (this, error);

        /* on unhandled failures, unwind */
        if (op_ret) {
                rio_local_wipe (local);
                if (infop == GF_FOP_MKDIR)
                        STACK_UNWIND (mkdir, frame, op_ret, op_errno, inode,
                                      buf, NULL, NULL, xdata);
                /* TODO: When icreate is added, add an unwind
                condition for the same */
                return 0;
        }

        /* Stash the inode and stat information to return when namelink
        completes */
        rio_iatt_copy (&local->riolocal_stbuf, buf);
        local->riolocal_inode = inode_ref (inode);
        if (xdata)
                local->riolocal_xdata_out = dict_ref (xdata);

        if (infop == GF_FOP_MKDIR) {
                ret = rio_server_mkdir_namelink (frame, this, local);
        }
        /* TODO: When icreate is added, add an unwind condition for the same */
        return ret;
error:
        rio_local_wipe (local);
        if (infop == GF_FOP_MKDIR) {
                STACK_UNWIND (mkdir, frame, -1, errno, NULL, NULL, NULL, NULL,
                              NULL);
        }
bailout:
        return -1;
}

/* MKDIR call
Mkdir is a transaction, where it would create the inode for the directory, and
then link in the name for the directory under the parent. The inode can reside
in a totally different MDS than the name. There is hence a need to maintain a
journal for reclaiming orphan inodes among other coordination to be done in this
call.

Generic structure:
        - lock the layout
        - check if layout version is in agreement between client and MDS
        - mark the layout as in use (to prevent changes to the layout when
        FOPs are being processed)
        - Journal the OP
        - Prepare to WIND the Op to create the inode
        - WIND inode creation to the right MDS
        - On the return, WIND namelink to the local MDS
*/
int32_t
rio_server_mkdir (call_frame_t *frame, xlator_t *this,
                  loc_t *loc, mode_t mode, mode_t umask, dict_t *xdata)
{
        xlator_t *subvol;
        struct rio_conf *conf;
        struct rio_local *local;
        void *uuidreq;
        uuid_t gfid;
        loc_t inode_loc = {0,};
        int ret;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);
        VALIDATE_OR_GOTO (loc, error);
        VALIDATE_OR_GOTO (loc->name, error);

        /* TODO: layout checks and locks */
        /* TODO: journal work */

        /* Determine MDS to create inode in */
        /* NOTE: We use the already generated GFID, as that ensures enough
        randomness to give us a bucket ID distribution */
        ret = dict_get_ptr (xdata, "gfid-req", &uuidreq);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, errno,
                        RIO_MSG_LAYOUT_ERROR,
                        "Missing GFID in request data for creating directory"
                        " %s, under parent %s", loc->name,
                        uuid_utoa (loc->parent->gfid));
                errno = EINVAL;
                goto error;
        }
        gf_uuid_copy (gfid, uuidreq);

        /* Find MDS to redirect inode request to */
        subvol = layout_search (conf->riocnf_mdclayout, gfid);
        if (!subvol) {
                gf_msg (this->name, GF_LOG_ERROR, errno,
                        RIO_MSG_LAYOUT_ERROR,
                        "Unable to find subvolume for GFID %s,"
                        "failing directory creation of %s, under parent %s",
                        uuid_utoa (gfid), loc->name,
                        uuid_utoa (loc->parent->gfid));
                errno = EINVAL;
                goto error;
        }

        /* Generate a loc for icreate operation */
        rio_prepare_inode_loc (&inode_loc, loc->inode, gfid, _gf_true);

        /* Stash the request */
        local = rio_local_init (frame, conf, loc, NULL, xdata, GF_FOP_MKDIR);
        if (!local) {
                gf_msg (this->name, GF_LOG_ERROR, errno,
                        RIO_MSG_LOCAL_ERROR,
                        "Unable to store FOP in args for operation continuty,"
                        "failing directory creation of %s, under parent %s",
                        loc->name, uuid_utoa (loc->parent->gfid));
                errno = ENOMEM;
                goto error;
        }

        /* Wind the icreate to create the inode for the directory */
        STACK_WIND (frame, rio_server_icreate_cbk, subvol,
                    subvol->fops->icreate, &inode_loc, S_IFDIR | mode, xdata);
        loc_wipe (&inode_loc);
        return 0;
error:
        rio_local_wipe (local);
        loc_wipe (&inode_loc);
        STACK_UNWIND (mkdir, frame, -1, errno, NULL, NULL, NULL, NULL, NULL);
bailout:
        return -1;
}
