#!/usr/bin/python

import os
import sys

curdir = os.path.dirname(sys.argv[0])
gendir = os.path.join(curdir, '../../../../../libglusterfs/src')
sys.path.append(gendir)
from generator import ops, fop_subs, cbk_subs, generate

UNSUP_OP_FOP_TEMPLATE = """
int32_t
rio_client_@NAME@ (call_frame_t *frame, xlator_t *this,
                   @LONG_ARGS@)
{
#ifdef RIO_DEBUG
        if (this)
                gf_msg (this->name, GF_LOG_INFO, 0, 0,
                        "Unsupported @UPNAME@");
#endif

        STACK_UNWIND_STRICT (@NAME@, frame, -1, ENOTSUP,
                             @CBK_ERROR_ARGS@);
        return 0;
}
"""

COMMON_OP_CBK_TEMPLATE = """
int32_t
rio_client_@NAME@_cbk (call_frame_t *frame, void *cookie,
                       xlator_t *this, int32_t op_ret, int32_t op_errno,
                       @LONG_ARGS@)
{
        VALIDATE_OR_GOTO (frame, bailout);

        /* TODO: Handle ESTALELAYOUT (at which point start stashing loc, xdata
        and other relevant in args from the FOP call) */
        STACK_UNWIND (@NAME@, frame, op_ret, op_errno,
                      @SHORT_ARGS@);
bailout:
        return 0;
}
"""

ENTRY_OPS_FOP_TEMPLATE = """
int32_t
rio_client_@NAME@ (call_frame_t *frame, xlator_t *this,
                   @LONG_ARGS@)
{
        xlator_t *subvol;
        struct rio_conf *conf;
        uuid_t searchuuid;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);
        VALIDATE_OR_GOTO (loc, error);

        /* All entry ops should contain a parent and its inode for call
        redirection to the MDS that holds the right parent. */
        if (loc->parent && !gf_uuid_is_null (loc->parent->gfid)) {
                gf_uuid_copy (searchuuid, loc->parent->gfid);
        } else if (!gf_uuid_is_null (loc->pargfid)) {
                gf_uuid_copy (searchuuid, loc->pargfid);
        } else {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        RIO_MSG_MISSING_GFID,
                        "Missing parent GFID for entry operation @UPNAME@"
                        " on name %s with possible path %s",
                        (loc->name)? loc->name : "NULL",
                        (loc->path)? loc->path : "NULL");
                errno = EINVAL;
                goto error;
        }

        subvol = layout_search (conf->riocnf_mdclayout, searchuuid);
        if (!subvol) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        RIO_MSG_LAYOUT_ERROR,
                        "Unable to find subvolume for GFID %s",
                        uuid_utoa (searchuuid));
                errno = EINVAL;
                goto error;
        }

#ifdef RIO_DEBUG
        gf_msg (this->name, GF_LOG_INFO, 0, 0,
                "Sending @UPNAME@ to subvol %s", subvol->name);
#endif

        STACK_WIND (frame, rio_client_@NAME@_cbk, subvol,
                    subvol->fops->@NAME@,
                    @SHORT_ARGS@);

        return 0;
error:
        STACK_UNWIND (@NAME@, frame, -1, errno,
                      @CBK_ERROR_ARGS@);
        return 0;
bailout:
        return 0;
}
"""

INODE_OPS_FOP_TEMPLATE = """
int32_t
rio_client_@NAME@ (call_frame_t *frame, xlator_t *this,
                   @LONG_ARGS@)
{
        xlator_t *subvol;
        struct rio_conf *conf;
        uuid_t searchuuid;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);
        VALIDATE_OR_GOTO (loc, error);

        /* All inode based ops should contain loc->gfid or loc->inode->gfid
        for us to make progress */
        if ((loc->inode != NULL) && !gf_uuid_is_null (loc->inode->gfid)){
                gf_uuid_copy(searchuuid, loc->inode->gfid);
        } else if (!gf_uuid_is_null (loc->gfid)) {
                gf_uuid_copy(searchuuid, loc->gfid);
        } else {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        RIO_MSG_MISSING_GFID,
                        "Missing GFID for operation @UPNAME@"
                        " on name %s with possible path %s",
                        (loc->name)? loc->name : "NULL",
                        (loc->path)? loc->path : "NULL");
                errno = EINVAL;
                goto error;
        }

        subvol = layout_search (conf->riocnf_mdclayout, searchuuid);
        if (!subvol) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        RIO_MSG_LAYOUT_ERROR,
                        "Unable to find subvolume for GFID %s",
                        uuid_utoa (searchuuid));
                errno = EINVAL;
                goto error;
        }

#ifdef RIO_DEBUG
        gf_msg (this->name, GF_LOG_INFO, 0, 0,
                "Sending @UPNAME@ for gfid %s to subvol %s",
                uuid_utoa (loc->gfid), subvol->name);
#endif

        STACK_WIND (frame, rio_client_@NAME@_cbk, subvol,
                    subvol->fops->@NAME@,
                    @SHORT_ARGS@);

        return 0;
error:
        STACK_UNWIND (@NAME@, frame, -1, errno,
                      @CBK_ERROR_ARGS@);
        return 0;
bailout:
        return 0;
}
"""

DS_FD_OPS_FOP_TEMPLATE = """
int32_t
rio_client_@NAME@ (call_frame_t *frame, xlator_t *this,
                   @LONG_ARGS@)
{
        xlator_t *subvol;
        struct rio_conf *conf;
        uuid_t searchgfid;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);
        VALIDATE_OR_GOTO (fd, error);
        VALIDATE_OR_GOTO (fd->inode, error);

        /* All fd based ops should contain fd->inode->gfid for us to
        make progress */
        if (!gf_uuid_is_null (fd->inode->gfid)){
                gf_uuid_copy(searchgfid, fd->inode->gfid);
        } else {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        RIO_MSG_MISSING_GFID,
                        "Missing GFID for fd %p with  inode %p",
                        fd, fd->inode);
                errno = EINVAL;
                goto error;
        }

        subvol = layout_search (conf->riocnf_dclayout, searchgfid);
        if (!subvol) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        RIO_MSG_LAYOUT_ERROR,
                        "Unable to find subvolume for GFID %s",
                        uuid_utoa (searchgfid));
                errno = EINVAL;
                goto error;
        }

#ifdef RIO_DEBUG
        gf_msg (this->name, GF_LOG_INFO, 0, 0,
                "Sending @UPNAME@ to subvol %s", subvol->name);
#endif

        STACK_WIND (frame, rio_client_@NAME@_cbk, subvol,
                    subvol->fops->@NAME@,
                    @SHORT_ARGS@);

        return 0;
error:
        STACK_UNWIND (@NAME@, frame, -1, errno,
                      @CBK_ERROR_ARGS@);
        return 0;
bailout:
        return 0;
}
"""

FD_OPS_FOP_TEMPLATE = """
int32_t
rio_client_@NAME@ (call_frame_t *frame, xlator_t *this,
                   @LONG_ARGS@)
{
        xlator_t *subvol;
        struct rio_conf *conf;
        uuid_t searchgfid;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);
        VALIDATE_OR_GOTO (fd, error);
        VALIDATE_OR_GOTO (fd->inode, error);

        /* All fd based ops should contain fd->inode->gfid for us to
        make progress */
        if (!gf_uuid_is_null (fd->inode->gfid)){
                gf_uuid_copy(searchgfid, fd->inode->gfid);
        } else {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        RIO_MSG_MISSING_GFID,
                        "Missing GFID for fd %p with  inode %p",
                        fd, fd->inode);
                errno = EINVAL;
                goto error;
        }

        subvol = layout_search (conf->riocnf_mdclayout, searchgfid);
        if (!subvol) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        RIO_MSG_LAYOUT_ERROR,
                        "Unable to find subvolume for GFID %s",
                        uuid_utoa (searchgfid));
                errno = EINVAL;
                goto error;
        }

#ifdef RIO_DEBUG
        gf_msg (this->name, GF_LOG_INFO, 0, 0,
                "Sending @UPNAME@ to subvol %s", subvol->name);
#endif

        STACK_WIND (frame, rio_client_@NAME@_cbk, subvol,
                    subvol->fops->@NAME@,
                    @SHORT_ARGS@);

        return 0;
error:
        STACK_UNWIND (@NAME@, frame, -1, errno,
                      @CBK_ERROR_ARGS@);
        return 0;
bailout:
        return 0;
}
"""

# All xlator FOPs are covered in the following section just to create a clarity
# The lists themselves are not used.
entry_ops = ['mknod', 'mkdir', 'unlink', 'rmdir', 'symlink', 'rename', 'link',
             'create']
special_ops = ['statfs', 'lookup', 'ipc', 'compound', 'icreate', 'namelink']
ignored_ops = ['getspec']
inode_ops = ['stat', 'readlink', 'truncate', 'open', 'setxattr', 'getxattr',
             'removexattr', 'opendir', 'access', 'inodelk', 'entrylk',
             'xattrop', 'setattr', 'lease', 'getactivelk', 'setactivelk',
             'discover']
fd_ops = ['readv', 'writev', 'flush', 'fsync', 'fsyncdir', 'ftruncate',
          'fstat', 'lk', 'readdir', 'finodelk', 'fentrylk', 'fxattrop',
          'fsetxattr', 'fgetxattr', 'rchecksum', 'fsetattr', 'readdirp',
          'fremovexattr', 'fallocate', 'discard', 'zerofill', 'seek']

# These are the current actual lists used to generate the code
unsupported_ops = ['mknod', 'unlink', 'rmdir', 'symlink', 'rename',
                   'link',
                   'statfs', 'ipc', 'compound', 'icreate', 'namelink',
                   'readlink', 'opendir', 'discover',
                   'fsync', 'readdir', 'readdirp']
mdsonly_inode_ops = ['stat', 'truncate', 'open', 'setxattr', 'getxattr',
                     'removexattr', 'access', 'inodelk', 'entrylk', 'xattrop',
                     'setattr', 'lease', 'getactivelk', 'setactivelk']
mdsonly_fd_ops = ['flush', 'fsyncdir', 'fstat', 'lk', 'finodelk',
                  'fentrylk', 'fxattrop', 'fsetxattr', 'fgetxattr', 'fsetattr',
                  'fremovexattr']

mdsonly_entry_ops = ['mkdir', 'create']
dsonly_fd_ops = ['readv', 'writev', 'ftruncate', 'rchecksum', 'fallocate',
                 'discard', 'zerofill', 'seek']
dsonly_inode_ops = ['not-yet']
both_ops = ['statfs', 'fsync']


def gen_defaults():
    for name in ops:
        if name in unsupported_ops:
            print generate(UNSUP_OP_FOP_TEMPLATE, name, fop_subs)
        elif name in mdsonly_inode_ops:
            print generate(COMMON_OP_CBK_TEMPLATE, name, cbk_subs)
            print generate(INODE_OPS_FOP_TEMPLATE, name, fop_subs)
        elif name in mdsonly_fd_ops:
            print generate(COMMON_OP_CBK_TEMPLATE, name, cbk_subs)
            print generate(FD_OPS_FOP_TEMPLATE, name, fop_subs)
        elif name in mdsonly_entry_ops:
            print generate(COMMON_OP_CBK_TEMPLATE, name, cbk_subs)
            print generate(ENTRY_OPS_FOP_TEMPLATE, name, fop_subs)
        elif name in dsonly_fd_ops:
            print generate(COMMON_OP_CBK_TEMPLATE, name, cbk_subs)
            print generate(DS_FD_OPS_FOP_TEMPLATE, name, fop_subs)


for l in open(sys.argv[1], 'r').readlines():
    if l.find('#pragma generate') != -1:
        print "/* BEGIN GENERATED CODE - DO NOT MODIFY */"
        gen_defaults()
        print "/* END GENERATED CODE */"
    else:
        print l[:-1]
