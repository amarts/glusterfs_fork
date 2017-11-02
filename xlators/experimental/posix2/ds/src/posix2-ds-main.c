/*
  Copyright (c) 2016 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

/* File: posix2-ds-main.c
 * This file contains the xlator loading functions, FOP entry points
 * and options.
 */

#include "xlator.h"

#include "posix2-ds-fops.h"
#include "posix2-unsupported-fops.h"
#include "posix.h"

class_methods_t class_methods = {
        .init           = posix_init,
        .fini           = posix_fini,
        .reconfigure    = posix_reconfigure,
        .notify         = posix_notify
};

struct xlator_dumpops dumpops = {
        .priv    = posix_priv,
        .inode   = posix_inode,
};

struct xlator_fops fops = {
        .lookup         = posix2_ds_lookup,
        .stat           = posix2_unsupported_stat,
        .fstat          = posix2_unsupported_fstat,
        .truncate       = posix_truncate,
        .ftruncate      = posix_ftruncate,
        .access         = posix2_unsupported_access,
        .readlink       = posix2_unsupported_readlink,
        .mknod          = posix2_unsupported_mknod,
        .mkdir          = posix2_unsupported_mkdir,
        .unlink         = posix2_unsupported_unlink,
        .rmdir          = posix2_unsupported_rmdir,
        .symlink        = posix2_unsupported_symlink,
        .rename         = posix2_unsupported_rename,
        .link           = posix2_unsupported_link,
        .create         = posix2_unsupported_create,
        .open           = posix2_unsupported_open,
        .readv          = posix_readv,
        .writev         = posix_writev,
        .flush          = posix2_unsupported_flush,
        .fsync          = posix_fsync,
        .opendir        = posix2_unsupported_opendir,
        .readdir        = posix2_unsupported_readdir,
        .readdirp       = posix2_unsupported_readdirp,
        .fsyncdir       = posix2_unsupported_fsyncdir,
        .statfs         = posix_statfs,
        .setxattr       = posix2_unsupported_setxattr,
        .getxattr       = posix2_unsupported_getxattr,
        .fsetxattr      = posix2_unsupported_fsetxattr,
        .fgetxattr      = posix2_unsupported_fgetxattr,
        .removexattr    = posix2_unsupported_removexattr,
        .fremovexattr   = posix2_unsupported_fremovexattr,
        .lk             = posix_lk,
        .inodelk        = posix_inodelk,
        .finodelk       = posix_finodelk,
        .entrylk        = posix_entrylk,
        .fentrylk       = posix_fentrylk,
        .rchecksum      = posix_rchecksum,
        .xattrop        = posix2_unsupported_xattrop,
        .fxattrop       = posix2_unsupported_fxattrop,
        .setattr        = posix2_unsupported_setattr,
        .fsetattr       = posix2_unsupported_fsetattr,
        .fallocate      = posix_glfallocate,
        .discard        = posix_discard,
        .zerofill       = posix_zerofill,
        .ipc            = posix_ipc,
#ifdef HAVE_SEEK_HOLE
        .seek           = posix_seek,
#endif
        .lease          = posix_lease,
/*        .compound       = posix2_unsupported_compound, */
/*        .getactivelk    = posix2_unsupported_getactivelk,*/
/*        .setactivelk    = posix2_unsupported_setactivelk,*/
};

struct xlator_cbks cbks = {
        .release     = posix_release,
        .releasedir  = posix_releasedir,
        .forget      = posix_forget
};
