/*
  Copyright (c) 2006-2010 Gluster, Inc. <http://www.gluster.com>
  This file is part of GlusterFS.

  GlusterFS is free software; you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation; either version 3 of the License,
  or (at your option) any later version.

  GlusterFS is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see
  <http://www.gnu.org/licenses/>.
*/

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#define __XOPEN_SOURCE 500

#include <stdint.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <ftw.h>
#include <sys/stat.h>

#ifndef GF_BSD_HOST_OS
#include <alloca.h>
#endif /* GF_BSD_HOST_OS */

#include "glusterfs.h"
#include "md5.h"
#include "checksum.h"
#include "dict.h"
#include "logging.h"
#include "cdp.h"
#include "xlator.h"
#include "defaults.h"
#include "common-utils.h"
#include "compat-errno.h"
#include "compat.h"
#include "byte-order.h"
#include "syscall.h"
#include "statedump.h"
#include "locking.h"
#include "timer.h"
#include "glusterfs3-xdr.h"
#include "hashfn.h"


#undef HAVE_SET_FSID
#ifdef HAVE_SET_FSID

#define DECLARE_OLD_FS_ID_VAR uid_t old_fsuid; gid_t old_fsgid;

#define SET_FS_ID(uid, gid) do {                \
                old_fsuid = setfsuid (uid);     \
                old_fsgid = setfsgid (gid);     \
        } while (0)

#define SET_TO_OLD_FS_ID() do {                 \
                setfsuid (old_fsuid);           \
                setfsgid (old_fsgid);           \
        } while (0)

#else

#define DECLARE_OLD_FS_ID_VAR
#define SET_FS_ID(uid, gid)
#define SET_TO_OLD_FS_ID()

#endif

int
cdp_forget (xlator_t *this, inode_t *inode)
{
        return 0;
}

/* Regular fops */

int32_t
cdp_lookup (call_frame_t *frame, xlator_t *this,
              loc_t *loc, dict_t *xattr_req)
{
        struct iatt buf          = {0, };
        char *      real_path    = NULL;
        int32_t     op_ret       = -1;
        int32_t     entry_ret    = 0;
        int32_t     op_errno     = 0;
        dict_t *    xattr        = NULL;
        char *      parentpath   = NULL;
        struct iatt postparent   = {0,};
        uuid_t      gfid         = {0,};

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);
        VALIDATE_OR_GOTO (loc->path, out);

        MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        if (!real_path) {
                /* Get the gfid path from parent */
                if (loc->parent)
                        MAKE_GFID_PATH (real_path, this, loc->parent->gfid);
                else {
                        gf_log (this->name, GF_LOG_ERROR,
                                "inode with no gfid and parent %s",
                                loc->path);
                        goto out;
                }

                strcat (real_path, loc->name);
                op_ret = sys_lgetxattr (real_path, GFID_XATTR_KEY, gfid, 16);
                /* Return value of getxattr */
                if (op_ret == 16)
                        op_ret = 0;
                if (op_ret) {
                        op_errno = errno;
                        if ((op_ret == -1) && (errno == ENOENT)) {
                                entry_ret = -1;
                                goto parent;
                        }
                        goto out;
                }
                MAKE_GFID_PATH (real_path, this, gfid);
        } else {
                uuid_copy (gfid, loc->inode->gfid);
        }

        op_ret   = cdp_lstat_with_gfid (this, real_path, &buf, gfid);
        op_errno = errno;
        if (op_ret == -1) {
                if (op_errno != ENOENT) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "lstat on %s failed: %s",
                                loc->path, strerror (op_errno));
                }

                entry_ret = -1;
                goto parent;
        }

        if (xattr_req && (op_ret == 0)) {
                xattr = cdp_lookup_xattr_fill (this, real_path, loc,
                                                 xattr_req, &buf);
        }

parent:
        if (loc->parent) {
                MAKE_GFID_PATH (parentpath, this, loc->parent->gfid);

                op_ret = cdp_lstat_with_gfid (this, parentpath, &postparent,
                                                loc->parent->gfid);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "post-operation lstat on parent of %s failed: %s",
                                loc->path, strerror (op_errno));
                        goto out;
                }
        }

        op_ret = entry_ret;
out:
        if (xattr)
                dict_ref (xattr);

        STACK_UNWIND_STRICT (lookup, frame, op_ret, op_errno,
                             (loc)?loc->inode:NULL, &buf, xattr, &postparent);

        if (xattr)
                dict_unref (xattr);

        return 0;
}


int32_t
cdp_stat (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
        struct iatt           buf       = {0,};
        char *                real_path = NULL;
        int32_t               op_ret    = -1;
        int32_t               op_errno  = 0;
        struct cdp_private *priv      = NULL;

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        SET_FS_ID (frame->root->uid, frame->root->gid);
        MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        op_ret = cdp_lstat_with_gfid (this, real_path, &buf,
                                        loc->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "lstat on %s failed: %s", loc->path,
                        strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID();
        STACK_UNWIND_STRICT (stat, frame, op_ret, op_errno, &buf);

        return 0;
}

static int
cdp_do_chmod (xlator_t *this, const char *path, struct iatt *stbuf)
{
        int32_t     ret = -1;
        mode_t      mode = 0;
        struct stat stat;
        int         is_symlink = 0;

        ret = sys_lstat (path, &stat);
        if (ret != 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "lstat failed: %s (%s)", path, strerror (errno));
                goto out;
        }

        if (S_ISLNK (stat.st_mode))
                is_symlink = 1;

        mode = st_mode_from_ia (stbuf->ia_prot, stbuf->ia_type);
        ret = lchmod (path, mode);
        if ((ret == -1) && (errno == ENOSYS)) {
                /* in Linux symlinks are always in mode 0777 and no
                   such call as lchmod exists.
                */
                gf_log (this->name, GF_LOG_DEBUG,
                        "%s (%s)", path, strerror (errno));
                if (is_symlink) {
                        ret = 0;
                        goto out;
                }

                ret = chmod (path, mode);
        }
out:
        return ret;
}

static int
cdp_do_chown (xlator_t *this,
                const char *path,
                struct iatt *stbuf,
                int32_t valid)
{
        int32_t ret = -1;
        uid_t uid = -1;
        gid_t gid = -1;

        if (valid & GF_SET_ATTR_UID)
                uid = stbuf->ia_uid;

        if (valid & GF_SET_ATTR_GID)
                gid = stbuf->ia_gid;

        ret = lchown (path, uid, gid);

        return ret;
}

static int
cdp_do_utimes (xlator_t *this,
                 const char *path,
                 struct iatt *stbuf)
{
        int32_t ret = -1;
        struct timeval tv[2]     = {{0,},{0,}};
        struct stat stat;
        int    is_symlink = 0;

        ret = sys_lstat (path, &stat);
        if (ret != 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "%s (%s)", path, strerror (errno));
                goto out;
        }

        if (S_ISLNK (stat.st_mode))
                is_symlink = 1;

        tv[0].tv_sec  = stbuf->ia_atime;
        tv[0].tv_usec = stbuf->ia_atime_nsec / 1000;
        tv[1].tv_sec  = stbuf->ia_mtime;
        tv[1].tv_usec = stbuf->ia_mtime_nsec / 1000;

        ret = lutimes (path, tv);
        if ((ret == -1) && (errno == ENOSYS)) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "%s (%s)", path, strerror (errno));
                if (is_symlink) {
                        ret = 0;
                        goto out;
                }

                ret = utimes (path, tv);
        }

out:
        return ret;
}

int
cdp_setattr (call_frame_t *frame, xlator_t *this,
               loc_t *loc, struct iatt *stbuf, int32_t valid)
{
        int32_t        op_ret    = -1;
        int32_t        op_errno  = 0;
        char *         real_path = 0;
        struct iatt    statpre     = {0,};
        struct iatt    statpost    = {0,};

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);

        SET_FS_ID (frame->root->uid, frame->root->gid);
        MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        op_ret = cdp_lstat_with_gfid (this, real_path, &statpre,
                                        loc->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "setattr (lstat) on %s failed: %s", real_path,
                        strerror (op_errno));
                goto out;
        }

        if (valid & GF_SET_ATTR_MODE) {
                op_ret = cdp_do_chmod (this, real_path, stbuf);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "setattr (chmod) on %s failed: %s", real_path,
                                strerror (op_errno));
                        goto out;
                }
        }

        if (valid & (GF_SET_ATTR_UID | GF_SET_ATTR_GID)){
                op_ret = cdp_do_chown (this, real_path, stbuf, valid);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "setattr (chown) on %s failed: %s", real_path,
                                strerror (op_errno));
                        goto out;
                }
        }

        if (valid & (GF_SET_ATTR_ATIME | GF_SET_ATTR_MTIME)) {
                op_ret = cdp_do_utimes (this, real_path, stbuf);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "setattr (utimes) on %s failed: %s", real_path,
                                strerror (op_errno));
                        goto out;
                }
        }

        if (!valid) {
                op_ret = lchown (real_path, -1, -1);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "lchown (%s, -1, -1) failed => (%s)",
                                real_path, strerror (op_errno));

                        goto out;
                }
        }

        op_ret = cdp_lstat_with_gfid (this, real_path, &statpost,
                                        loc->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "setattr (lstat) on %s failed: %s", real_path,
                        strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (setattr, frame, op_ret, op_errno,
                             &statpre, &statpost);

        return 0;
}

int32_t
cdp_do_fchown (xlator_t *this,
                 int fd,
                 struct iatt *stbuf,
                 int32_t valid)
{
        int   ret      = -1;
        uid_t uid = -1;
        gid_t gid = -1;

        if (valid & GF_SET_ATTR_UID)
                uid = stbuf->ia_uid;

        if (valid & GF_SET_ATTR_GID)
                gid = stbuf->ia_gid;

        ret = fchown (fd, uid, gid);

        return ret;
}


int32_t
cdp_do_fchmod (xlator_t *this,
                 int fd, struct iatt *stbuf)
{
        mode_t  mode = 0;

        mode = st_mode_from_ia (stbuf->ia_prot, stbuf->ia_type);
        return fchmod (fd, mode);
}

static int
cdp_do_futimes (xlator_t *this,
                  int fd,
                  struct iatt *stbuf)
{
        gf_log (this->name, GF_LOG_WARNING, "function not implemented fd(%d)", fd);

        errno = ENOSYS;
        return -1;
}

int
cdp_fsetattr (call_frame_t *frame, xlator_t *this,
                fd_t *fd, struct iatt *stbuf, int32_t valid)
{
        int32_t        op_ret    = -1;
        int32_t        op_errno  = 0;
        struct iatt    statpre     = {0,};
        struct iatt    statpost    = {0,};
        struct cdp_fd *pfd = NULL;
        uint64_t         tmp_pfd = 0;
        int32_t          ret = -1;

        DECLARE_OLD_FS_ID_VAR;

        SET_FS_ID (frame->root->uid, frame->root->gid);

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                op_errno = -ret;
                gf_log (this->name, GF_LOG_DEBUG,
                        "pfd is NULL from fd=%p", fd);
                goto out;
        }
        pfd = (struct cdp_fd *)(long)tmp_pfd;

        op_ret = cdp_fstat_with_gfid (this, pfd->fd, &statpre,
                                        fd->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "fsetattr (fstat) failed on fd=%p: %s", fd,
                        strerror (op_errno));
                goto out;
        }

        if (valid & GF_SET_ATTR_MODE) {
                op_ret = cdp_do_fchmod (this, pfd->fd, stbuf);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "fsetattr (fchmod) failed on fd=%p: %s",
                                fd, strerror (op_errno));
                        goto out;
                }
        }

        if (valid & (GF_SET_ATTR_UID | GF_SET_ATTR_GID)) {
                op_ret = cdp_do_fchown (this, pfd->fd, stbuf, valid);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "fsetattr (fchown) failed on fd=%p: %s",
                                fd, strerror (op_errno));
                        goto out;
                }

        }

        if (valid & (GF_SET_ATTR_ATIME | GF_SET_ATTR_MTIME)) {
                op_ret = cdp_do_futimes (this, pfd->fd, stbuf);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "fsetattr (futimes) on failed fd=%p: %s", fd,
                                strerror (op_errno));
                        goto out;
                }
        }

        if (!valid) {
                op_ret = fchown (pfd->fd, -1, -1);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "fchown (%d, -1, -1) failed => (%s)",
                                pfd->fd, strerror (op_errno));

                        goto out;
                }
        }

        op_ret = cdp_fstat_with_gfid (this, pfd->fd, &statpost,
                                        fd->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "fsetattr (fstat) failed on fd=%p: %s", fd,
                        strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (fsetattr, frame, op_ret, op_errno,
                             &statpre, &statpost);

        return 0;
}

int32_t
cdp_opendir (call_frame_t *frame, xlator_t *this,
               loc_t *loc, fd_t *fd)
{
        char *            real_path = NULL;
        int32_t           op_ret    = -1;
        int32_t           op_errno  = EINVAL;
        DIR *             dir       = NULL;
        struct cdp_fd * pfd       = NULL;

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);
        VALIDATE_OR_GOTO (loc->path, out);
        VALIDATE_OR_GOTO (fd, out);

        SET_FS_ID (frame->root->uid, frame->root->gid);
        MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        dir = opendir (real_path);

        if (dir == NULL) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "opendir failed on %s: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        op_ret = dirfd (dir);
        if (op_ret < 0) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "dirfd() failed on %s: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        pfd = GF_CALLOC (1, sizeof (*pfd), gf_cdp_mt_cdp_fd);
        if (!pfd) {
                op_errno = errno;
                goto out;
        }

        pfd->dir = dir;
        pfd->fd = dirfd (dir);
        pfd->path = gf_strdup (real_path);
        if (!pfd->path) {
                goto out;
        }

        op_ret = fd_ctx_set (fd, this, (uint64_t)(long)pfd);
        if (op_ret)
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to set the fd context path=%s fd=%p",
                        loc->path, fd);

        op_ret = 0;

out:
        if (op_ret == -1) {
                if (dir) {
                        closedir (dir);
                        dir = NULL;
                }
                if (pfd) {
                        if (pfd->path)
                                GF_FREE (pfd->path);
                        GF_FREE (pfd);
                        pfd = NULL;
                }
        }

        SET_TO_OLD_FS_ID ();
        STACK_UNWIND_STRICT (opendir, frame, op_ret, op_errno, fd);
        return 0;
}

int32_t
cdp_releasedir (xlator_t *this,
                  fd_t *fd)
{
        struct cdp_fd * pfd      = NULL;
        uint64_t          tmp_pfd  = 0;
        int               ret      = 0;

        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        ret = fd_ctx_del (fd, this, &tmp_pfd);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "pfd from fd=%p is NULL", fd);
                goto out;
        }

        pfd = (struct cdp_fd *)(long)tmp_pfd;
        if (!pfd->dir) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd->dir is NULL for fd=%p path=%s",
                        fd, pfd->path ? pfd->path : "<NULL>");
                goto out;
        }

        if (!pfd->path) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd->path was NULL. fd=%p pfd=%p",
                        fd, pfd);
        }

        closedir (pfd->dir);

        /* Snapshoting comes here */
out:
        if (pfd) {
                if (pfd->path)
                        GF_FREE (pfd->path);

                GF_FREE (pfd);
        }

        return 0;
}


int32_t
cdp_readlink (call_frame_t *frame, xlator_t *this,
                loc_t *loc, size_t size)
{
        char *  dest      = NULL;
        int32_t op_ret    = -1;
        int32_t lstat_ret = -1;
        int32_t op_errno  = 0;
        char *  real_path = NULL;
        struct iatt stbuf = {0,};

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);

        SET_FS_ID (frame->root->uid, frame->root->gid);

        dest = alloca (size + 1);

        MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        op_ret = readlink (real_path, dest, size);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "readlink on %s failed: %s", loc->path,
                        strerror (op_errno));
                goto out;
        }

        dest[op_ret] = 0;

        lstat_ret = cdp_lstat_with_gfid (this, real_path, &stbuf,
                                           loc->inode->gfid);
        if (lstat_ret == -1) {
                op_ret = -1;
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "lstat on %s failed: %s", loc->path,
                        strerror (op_errno));
                goto out;
        }

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (readlink, frame, op_ret, op_errno, dest, &stbuf);

        return 0;
}


int
cdp_mknod (call_frame_t *frame, xlator_t *this,
             loc_t *loc, mode_t mode, dev_t dev, dict_t *params)
{
        int                   tmp_fd      = 0;
        int32_t               op_ret      = -1;
        int32_t               op_errno    = 0;
        char                 *real_path   = 0;
        struct iatt           stbuf       = { 0, };
        char                  was_present = 1;
        struct cdp_private *priv        = NULL;
        gid_t                 gid         = 0;
        struct iatt           preparent = {0,};
        struct iatt           postparent = {0,};
        char                 *parentpath = NULL;
        uuid_t                gfid = {0,};
        struct stat           tmpbuf = {0,};
        char                 *gfid_path = NULL;

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        MAKE_GFID_PATH (real_path, this, loc->parent->gfid);
        MAKE_GFID_PATH (parentpath, this, loc->parent->gfid);

        gid = frame->root->gid;

        op_ret = setgid_override (this, real_path, &gid);
        if (op_ret < 0) {
                op_errno = -op_ret;
                op_ret = -1;
                goto out;
        }

        SET_FS_ID (frame->root->uid, gid);

        op_ret = cdp_lstat_with_gfid (this, parentpath, &preparent,
                                        loc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "pre-operation lstat on parent of %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        {
                /* Create a entry in parent */
                strcat (real_path, loc->name);

                op_ret = stat (real_path, &tmpbuf);
                if ((op_ret == -1) && (errno == ENOENT))
                        was_present = 0;

                op_ret = mknod (real_path, mode, dev);
                if (op_ret == -1) {
                        op_errno = errno;
                        if ((op_errno == EINVAL) && S_ISREG (mode)) {
                                /* Over Darwin, mknod with (S_IFREG|mode)
                                   doesn't work */
                                tmp_fd = creat (real_path, mode);
                                if (tmp_fd == -1) {
                                        gf_log (this->name, GF_LOG_ERROR,
                                                "create failed on %s: %s",
                                                loc->path, strerror (errno));
                                        goto out;
                                }
                                close (tmp_fd);
                        } else {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "mknod on %s failed: %s", loc->path,
                                        strerror (op_errno));
                                goto out;
                        }
                }
                op_ret = cdp_gfid_set (this, real_path, params, gfid);
                if (op_ret) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "setting gfid on %s failed", loc->path);
                }

                create_gfid_directory_path (this, gfid, mode);
                MAKE_GFID_PATH (gfid_path, this, gfid);

                op_ret = link (real_path, gfid_path);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "hardlink on %s failed: %s", loc->path,
                                strerror (op_errno));
                        goto out;
                }
        }


#ifndef HAVE_SET_FSID
        op_ret = lchown (gfid_path, frame->root->uid, gid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "lchown on %s failed: %s", loc->path,
                        strerror (op_errno));
                goto out;
        }
#endif

        op_ret = cdp_acl_xattr_set (this, real_path, params);
        if (op_ret) {
                gf_log (this->name, GF_LOG_ERROR,
                        "setting ACLs on %s failed (%s)", loc->path,
                        strerror (errno));
        }

        op_ret = cdp_entry_create_xattr_set (this, real_path, params);
        if (op_ret) {
                gf_log (this->name, GF_LOG_ERROR,
                        "setting xattrs on %s failed (%s)", loc->path,
                        strerror (errno));
        }

        op_ret = cdp_lstat_with_gfid (this, gfid_path, &stbuf, gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "lstat on %s failed: %s", loc->path,
                        strerror (op_errno));
                goto out;
        }

        op_ret = cdp_lstat_with_gfid (this, parentpath, &postparent,
                                        loc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "post-operation lstat on parent of %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (mknod, frame, op_ret, op_errno,
                             (loc)?loc->inode:NULL, &stbuf, &preparent, &postparent);

        if ((op_ret == -1) && (!was_present)) {
                if (real_path)
                        unlink (real_path);
        }

        return 0;
}

int
cdp_mkdir (call_frame_t *frame, xlator_t *this,
             loc_t *loc, mode_t mode, dict_t *params)
{
        int32_t               op_ret      = -1;
        int32_t               op_errno    = 0;
        char                 *real_path   = NULL;
        struct iatt           stbuf       = {0, };
        char                  was_present = 1;
        struct cdp_private *priv        = NULL;
        gid_t                 gid         = 0;
        char                 *parentpath = NULL;
        struct iatt           preparent = {0,};
        struct iatt           postparent = {0,};
        uuid_t                gfid = {0,};
        char                 *gfid_path   = NULL;
        struct stat           tmpbuf = {0,};

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        MAKE_GFID_PATH (real_path, this, loc->parent->gfid);
        MAKE_GFID_PATH (parentpath, this, loc->parent->gfid);

        gid = frame->root->gid;

        op_ret = setgid_override (this, real_path, &gid);
        if (op_ret < 0) {
                op_errno = -op_ret;
                op_ret = -1;
                goto out;
        }

        SET_FS_ID (frame->root->uid, gid);
        op_ret = cdp_lstat_with_gfid (this, parentpath, &preparent,
                                        loc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "pre-operation lstat on parent of %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        {
                /* Create a entry in parent */
                strcat (real_path, loc->name);

                op_ret = stat (real_path, &tmpbuf);
                if ((op_ret == -1) && (errno == ENOENT))
                        was_present = 0;

                op_ret = mkdir (real_path, mode);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "mkdir of %s failed: %s", loc->path,
                                strerror (op_errno));
                        goto out;
                }
                op_ret = cdp_gfid_set (this, real_path, params, gfid);
                if (op_ret) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "setting gfid on %s failed", loc->path);
                }

                op_ret = create_gfid_directory_path (this, gfid, S_IFDIR | mode);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "mkdir of %s failed: %s", gfid_path,
                                strerror (op_errno));
                        goto out;
                }
                MAKE_GFID_PATH (gfid_path, this, gfid);
        }

#ifndef HAVE_SET_FSID
        op_ret = chown (gfid_path, frame->root->uid, gid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "chown on %s failed: %s", loc->path,
                        strerror (op_errno));
                goto out;
        }
#endif

        op_ret = cdp_acl_xattr_set (this, real_path, params);
        if (op_ret) {
                gf_log (this->name, GF_LOG_ERROR,
                        "setting ACLs on %s failed (%s)", loc->path,
                        strerror (errno));
        }

        op_ret = cdp_entry_create_xattr_set (this, real_path, params);
        if (op_ret) {
                gf_log (this->name, GF_LOG_ERROR,
                        "setting xattrs on %s failed (%s)", loc->path,
                        strerror (errno));
        }

        op_ret = cdp_lstat_with_gfid (this, gfid_path, &stbuf, gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "lstat on %s failed: %s", loc->path,
                        strerror (op_errno));
                goto out;
        }

        op_ret = cdp_lstat_with_gfid (this, parentpath, &postparent,
                                        loc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "post-operation lstat on parent of %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (mkdir, frame, op_ret, op_errno,
                             (loc)?loc->inode:NULL, &stbuf, &preparent, &postparent);

        if ((op_ret == -1) && (!was_present)) {
                if (real_path)
                        sys_unlink (real_path);
        }

        return 0;
}


int32_t
cdp_unlink (call_frame_t *frame, xlator_t *this,
              loc_t *loc)
{
        int32_t                  op_ret    = -1;
        int32_t                  op_errno  = 0;
        char                    *real_path = NULL;
        char                    *parentpath = NULL;
        struct iatt            preparent = {0,};
        struct iatt            postparent = {0,};

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);

        SET_FS_ID (frame->root->uid, frame->root->gid);
        MAKE_GFID_PATH (real_path, this, loc->parent->gfid);
        MAKE_GFID_PATH (parentpath, this, loc->parent->gfid);

        op_ret = cdp_lstat_with_gfid (this, parentpath, &preparent,
                                        loc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "pre-operation lstat on parent of %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        /* Need some enhancement */
        strcat (real_path, loc->name);

        op_ret = sys_unlink (real_path);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "unlink of %s failed: %s", loc->path,
                        strerror (op_errno));
                goto out;
        }

        /* TODO: this info can be used as 'trash' feature, if we don't
           delete the hardlink file */
        gf_log (this->name, GF_LOG_DEBUG, "deleted %s with gfid %s",
                loc->path, uuid_utoa (loc->inode->gfid));

        op_ret = cdp_lstat_with_gfid (this, parentpath, &postparent,
                                        loc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "post-operation lstat on parent of %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (unlink, frame, op_ret, op_errno,
                             &preparent, &postparent);

        return 0;
}


int
cdp_rmdir (call_frame_t *frame, xlator_t *this,
             loc_t *loc, int flags)
{
        int32_t op_ret    = -1;
        int32_t op_errno  = 0;
        char *  real_path = NULL;
        char *  parentpath = NULL;
        struct iatt   preparent = {0,};
        struct iatt   postparent = {0,};
        struct cdp_private    *priv      = NULL;
        char *  gfid_path = NULL;

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);

        priv = this->private;

        SET_FS_ID (frame->root->uid, frame->root->gid);
        MAKE_GFID_PATH (gfid_path, this, loc->inode->gfid);
        MAKE_GFID_PATH (real_path, this, loc->parent->gfid);
        MAKE_GFID_PATH (parentpath, this, loc->parent->gfid);

        op_ret = cdp_lstat_with_gfid (this, parentpath, &preparent,
                                        loc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "pre-operation lstat on parent of %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        strcat (real_path, loc->name);

        op_ret = rmdir (gfid_path);
        op_errno = errno;

        if (op_errno == EEXIST)
                /* Solaris sets errno = EEXIST instead of ENOTEMPTY */
                op_errno = ENOTEMPTY;

        if (!op_ret)
                op_ret = rmdir (real_path);

        if (op_ret == -1) {
                gf_log (this->name,
                        (op_errno == ENOTEMPTY) ? GF_LOG_DEBUG : GF_LOG_ERROR,
                        "rmdir on %s failed %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        op_ret = cdp_lstat_with_gfid (this, parentpath, &postparent,
                                        loc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "post-operation lstat on parent of %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (rmdir, frame, op_ret, op_errno,
                             &preparent, &postparent);

        return 0;
}


int
cdp_symlink (call_frame_t *frame, xlator_t *this,
               const char *linkname, loc_t *loc, dict_t *params)
{
        int32_t               op_ret      = -1;
        int32_t               op_errno    = 0;
        char *                real_path   = 0;
        struct iatt           stbuf       = { 0, };
        struct cdp_private *priv        = NULL;
        gid_t                 gid         = 0;
        char                  was_present = 1;
        char                 *parentpath = NULL;
        struct iatt           preparent = {0,};
        struct iatt           postparent = {0,};
        uuid_t                gfid = {0,};
        struct stat           tmpbuf = {0,};
        char                 *gfid_path = NULL;

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (linkname, out);
        VALIDATE_OR_GOTO (loc, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        MAKE_GFID_PATH (real_path, this, loc->parent->gfid);
        MAKE_GFID_PATH (parentpath, this, loc->parent->gfid);

        gid = frame->root->gid;

        op_ret = setgid_override (this, real_path, &gid);
        if (op_ret < 0) {
                op_errno = -op_ret;
                op_ret = -1;
                goto out;
        }

        SET_FS_ID (frame->root->uid, gid);

        op_ret = cdp_lstat_with_gfid (this, parentpath, &preparent, NULL);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "pre-operation lstat on parent of %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        {
                /* Create a entry in parent */
                strcat (real_path, loc->name);

                op_ret = stat (real_path, &tmpbuf);
                if ((op_ret == -1) && (errno == ENOENT))
                        was_present = 0;

                op_ret = symlink (linkname, real_path);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "symlink of %s --> %s failed: %s",
                                loc->path, linkname, strerror (op_errno));
                        goto out;
                }

                op_ret = cdp_gfid_set (this, real_path, params, gfid);
                if (op_ret) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "setting gfid on %s failed", loc->path);
                }

                create_gfid_directory_path (this, gfid, S_IFLNK | 0777);
                MAKE_GFID_PATH (gfid_path, this, gfid);

                op_ret = link (real_path, gfid_path);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "hardlink of %s --> %s failed: %s",
                                real_path, gfid_path, strerror (op_errno));
                        goto out;
                }
        }

#ifndef HAVE_SET_FSID
        op_ret = lchown (gfid_path, frame->root->uid, gid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "lchown failed on %s: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }
#endif

        op_ret = cdp_acl_xattr_set (this, real_path, params);
        if (op_ret) {
                gf_log (this->name, GF_LOG_ERROR,
                        "setting ACLs on %s failed (%s)", loc->path,
                        strerror (errno));
        }

        op_ret = cdp_entry_create_xattr_set (this, real_path, params);
        if (op_ret) {
                gf_log (this->name, GF_LOG_ERROR,
                        "setting xattrs on %s failed (%s)", loc->path,
                        strerror (errno));
        }

        op_ret = cdp_lstat_with_gfid (this, real_path, &stbuf, gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "lstat failed on %s: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        op_ret = cdp_lstat_with_gfid (this, parentpath, &postparent,
                                        loc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "post-operation lstat on parent of %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:

        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (symlink, frame, op_ret, op_errno,
                             (loc)?loc->inode:NULL, &stbuf, &preparent, &postparent);

        if ((op_ret == -1) && (!was_present)) {
                unlink (real_path);
        }

        return 0;
}


int
cdp_rename (call_frame_t *frame, xlator_t *this,
              loc_t *oldloc, loc_t *newloc)
{
        int32_t             op_ret         = -1;
        int32_t             op_errno       = 0;
        char               *real_oldpath   = NULL;
        char               *real_newpath   = NULL;
        struct iatt         stbuf          = {0, };
        struct cdp_private *priv           = NULL;
        char                was_present    = 1;
        char               *oldparentpath  = NULL;
        char               *newparentpath  = NULL;
        struct iatt         preoldparent   = {0, };
        struct iatt         postoldparent  = {0, };
        struct iatt         prenewparent   = {0, };
        struct iatt         postnewparent  = {0, };
        char                olddirid[64]   = {0,} ;
        char                newdirid[64]   = {0,};
        struct stat         tmpbuf         = {0,};
        uuid_t              newdir_gfid    = {0,};

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (oldloc, out);
        VALIDATE_OR_GOTO (newloc, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        SET_FS_ID (frame->root->uid, frame->root->gid);
        MAKE_GFID_PATH (real_oldpath, this, oldloc->parent->gfid);
        MAKE_GFID_PATH (real_newpath, this, newloc->parent->gfid);

        MAKE_GFID_PATH (newparentpath, this, newloc->parent->gfid);
        MAKE_GFID_PATH (oldparentpath, this, oldloc->parent->gfid);

        op_ret = cdp_lstat_with_gfid (this, oldparentpath, &preoldparent,
                                      oldloc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "pre-operation lstat on parent of %s failed: %s",
                        oldloc->path, strerror (op_errno));
                goto out;
        }

        op_ret = cdp_lstat_with_gfid (this, newparentpath, &prenewparent,
                                      newloc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "pre-operation lstat on parent of %s failed: %s",
                        newloc->path, strerror (op_errno));
                goto out;
        }

        strcat (real_oldpath, oldloc->name);
        strcat (real_newpath, newloc->name);

        op_ret = stat (real_newpath, &tmpbuf);
        if ((op_ret == -1) && (errno == ENOENT))
                was_present = 0;

        if (!op_ret && S_ISDIR (tmpbuf.st_mode) &&
            (IA_ISDIR (oldloc->inode->ia_type))) {
                /* Need to check destination for empty or not */
                if (!is_gfid_dir_empty (this, real_newpath)) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "rename of %s to %s failed: %s",
                                oldloc->path, newloc->path,
                                strerror (ENOTEMPTY));
                        op_ret = -1;
                        op_errno = ENOTEMPTY;
                        goto out;
                }
        }

        if (was_present && S_ISDIR(tmpbuf.st_mode) && !newloc->inode) {
                gf_log (this->name, GF_LOG_WARNING,
                        "found directory at %s while expecting ENOENT",
                        real_newpath);
                op_ret = -1;
                op_errno = EEXIST;
                goto out;
        }

        if (was_present && S_ISDIR(tmpbuf.st_mode)) {
                op_ret = sys_lgetxattr (real_newpath, GFID_XATTR_KEY,
                                        newdir_gfid, 16);
                if ((op_ret == 16) &&
                    uuid_compare (newloc->inode->gfid, newdir_gfid)) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "found directory %s at %s while renaming %s",
                                uuid_utoa_r (newloc->inode->gfid, olddirid),
                                real_newpath, uuid_utoa_r (newdir_gfid, newdirid));
                        op_ret = -1;
                        op_errno = EEXIST;
                        goto out;
                }
        }

        op_ret = sys_rename (real_oldpath, real_newpath);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name,
                        (op_errno == ENOTEMPTY ? GF_LOG_DEBUG : GF_LOG_ERROR),
                        "rename of %s to %s failed: %s",
                        oldloc->path, newloc->path, strerror (op_errno));
                goto out;
        }

        op_ret = cdp_lstat_with_gfid (this, real_newpath, &stbuf,
                                      oldloc->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "lstat on %s failed: %s",
                        real_newpath, strerror (op_errno));
                goto out;
        }

        op_ret = cdp_lstat_with_gfid (this, oldparentpath, &postoldparent,
                                      oldloc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "post-operation lstat on parent of %s failed: %s",
                        oldloc->path, strerror (op_errno));
                goto out;
        }

        op_ret = cdp_lstat_with_gfid (this, newparentpath, &postnewparent,
                                        newloc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "post-operation lstat on parent of %s failed: %s",
                        newloc->path, strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:

        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (rename, frame, op_ret, op_errno, &stbuf,
                             &preoldparent, &postoldparent,
                             &prenewparent, &postnewparent);

        if ((op_ret == -1) && !was_present) {
                unlink (real_newpath);
        }

        return 0;
}


int
cdp_link (call_frame_t *frame, xlator_t *this,
            loc_t *oldloc, loc_t *newloc)
{
        int32_t               op_ret       = -1;
        int32_t               op_errno     = 0;
        char                 *real_oldpath = 0;
        char                 *real_newpath = 0;
        struct iatt           stbuf        = {0, };
        struct cdp_private *priv         = NULL;
        char                  was_present  = 1;
        char                 *newparentpath = NULL;
        struct iatt           preparent = {0,};
        struct iatt           postparent = {0,};

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (oldloc, out);
        VALIDATE_OR_GOTO (newloc, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        SET_FS_ID (frame->root->uid, frame->root->gid);
        MAKE_GFID_PATH (real_oldpath, this, oldloc->inode->gfid);
        MAKE_GFID_PATH (newparentpath, this, newloc->parent->gfid);
        MAKE_GFID_PATH (real_newpath, this, newloc->parent->gfid);

        op_ret = cdp_lstat_with_gfid (this, newparentpath, &preparent,
                                        newloc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR, "lstat failed: %s: %s",
                        newparentpath, strerror (op_errno));
                goto out;
        }

        strcat (real_newpath, newloc->name);

        op_ret = link (real_oldpath, real_newpath);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "link %s to %s failed: %s",
                        oldloc->path, newloc->path, strerror (op_errno));
                goto out;
        }

        op_ret = cdp_lstat_with_gfid (this, real_newpath, &stbuf,
                                        oldloc->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "lstat on %s failed: %s",
                        real_newpath, strerror (op_errno));
                goto out;
        }

        op_ret = cdp_lstat_with_gfid (this, newparentpath, &postparent,
                                        newloc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR, "lstat failed: %s: %s",
                        newparentpath, strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (link, frame, op_ret, op_errno,
                             (oldloc)?oldloc->inode:NULL, &stbuf, &preparent,
                             &postparent);

        if ((op_ret == -1) && (!was_present)) {
                unlink (real_newpath);
        }

        return 0;
}

int32_t
cdp_truncate (call_frame_t *frame, xlator_t *this, loc_t *loc, off_t offset)
{
        int32_t               op_ret    = -1;
        int32_t               op_errno  = 0;
        char                 *real_path = 0;
        struct cdp_private *priv      = NULL;
        struct iatt           prebuf    = {0,};
        struct iatt           postbuf   = {0,};

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        SET_FS_ID (frame->root->uid, frame->root->gid);
        MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        op_ret = cdp_lstat_with_gfid (this, real_path, &prebuf,
                                        loc->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "pre-operation lstat on %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        op_ret = truncate (real_path, offset);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "truncate on %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        op_ret = cdp_lstat_with_gfid (this, real_path, &postbuf,
                                        loc->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR, "lstat on %s failed: %s",
                        real_path, strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (truncate, frame, op_ret, op_errno,
                             &prebuf, &postbuf);

        return 0;
}


int32_t
cdp_create (call_frame_t *frame, xlator_t *this,
              loc_t *loc, int32_t flags, mode_t mode,
              fd_t *fd, dict_t *params)
{
        int32_t                op_ret      = -1;
        int32_t                op_errno    = 0;
        int32_t                _fd         = -1;
        int                    _flags      = 0;
        char *                 real_path   = NULL;
        struct iatt            stbuf       = {0, };
        struct cdp_fd *      pfd         = NULL;
        struct cdp_private * priv        = NULL;
        char                   was_present = 1;
        uuid_t                gfid = {0,};
        struct stat           tmpbuf = {0,};
        char                 *gfid_path = NULL;

        gid_t                  gid         = 0;
        char                  *pathdup   = NULL;
        char                  *parentpath = NULL;
        struct iatt            preparent = {0,};
        struct iatt            postparent = {0,};

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (this->private, out);
        VALIDATE_OR_GOTO (loc, out);
        VALIDATE_OR_GOTO (fd, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        MAKE_GFID_PATH (real_path, this, loc->parent->gfid);
        MAKE_GFID_PATH (parentpath, this, loc->parent->gfid);

        gid = frame->root->gid;

        op_ret = setgid_override (this, real_path, &gid);
        if (op_ret < 0) {
                op_errno = -op_ret;
                op_ret = -1;
                goto out;
        }

        SET_FS_ID (frame->root->uid, gid);

        op_ret = cdp_lstat_with_gfid (this, parentpath, &preparent,
                                        loc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "pre-operation lstat on parent of %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        if (!flags) {
                _flags = O_CREAT | O_RDWR | O_EXCL;
        }
        else {
                _flags = flags | O_CREAT;
        }

        if (priv->o_direct)
                _flags |= O_DIRECT;

        {

                /* Create a entry in parent */
                strcat (real_path, loc->name);

                op_ret = stat (real_path, &tmpbuf);
                if ((op_ret == -1) && (errno == ENOENT))
                        was_present = 0;

                _fd = open (real_path, _flags, mode);
                if (_fd == -1) {
                        op_errno = errno;
                        op_ret = -1;
                        gf_log (this->name, GF_LOG_ERROR,
                                "open on %s failed: %s", loc->path,
                                strerror (op_errno));
                        goto out;
                }

                op_ret = cdp_gfid_set (this, real_path, params, gfid);
                if (op_ret) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "setting gfid on %s failed", loc->path);
                }

                op_ret = create_gfid_directory_path (this, gfid, S_IFREG | mode);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "mkdir of %s failed: %s", gfid_path,
                                strerror (op_errno));
                        goto out;
                }
                MAKE_GFID_PATH (gfid_path, this, gfid);

                op_ret = link (real_path, gfid_path);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "hardlink on %s failed: %s", loc->path,
                                strerror (op_errno));
                        goto out;
                }
        }

#ifndef HAVE_SET_FSID
        op_ret = chown (gfid_path, frame->root->uid, gid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "chown on %s failed: %s",
                        real_path, strerror (op_errno));
        }
#endif

        op_ret = cdp_acl_xattr_set (this, real_path, params);
        if (op_ret) {
                gf_log (this->name, GF_LOG_ERROR,
                        "setting ACLs on %s failed (%s)", loc->path,
                        strerror (errno));
        }

        op_ret = cdp_entry_create_xattr_set (this, real_path, params);
        if (op_ret) {
                gf_log (this->name, GF_LOG_ERROR,
                        "setting xattrs on %s failed (%s)", loc->path,
                        strerror (errno));
        }

        op_ret = cdp_fstat_with_gfid (this, _fd, &stbuf, gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "fstat on %d failed: %s", _fd, strerror (op_errno));
                goto out;
        }

        op_ret = cdp_lstat_with_gfid (this, parentpath, &postparent,
                                        loc->parent->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "post-operation lstat on parent of %s failed: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }

        op_ret = -1;
        pfd = GF_CALLOC (1, sizeof (*pfd), gf_cdp_mt_cdp_fd);
        if (!pfd) {
                op_errno = errno;
                goto out;
        }

        pfd->flags = flags;
        pfd->fd    = _fd;

        op_ret = fd_ctx_set (fd, this, (uint64_t)(long)pfd);
        if (op_ret)
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to set the fd context path=%s fd=%p",
                        loc->path, fd);

        LOCK (&priv->lock);
        {
                priv->nr_files++;
        }
        UNLOCK (&priv->lock);

        op_ret = 0;

out:
        if (pathdup)
                GF_FREE (pathdup);
        SET_TO_OLD_FS_ID ();

        if ((-1 == op_ret) && (_fd != -1)) {
                close (_fd);

                if (!was_present) {
                        if (real_path)
                                unlink (real_path);
                }
        }

        STACK_UNWIND_STRICT (create, frame, op_ret, op_errno,
                             fd, (loc)?loc->inode:NULL, &stbuf, &preparent,
                             &postparent);

        return 0;
}

int32_t
cdp_open (call_frame_t *frame, xlator_t *this,
            loc_t *loc, int32_t flags, fd_t *fd, int wbflags)
{
        int32_t               op_ret       = -1;
        int32_t               op_errno     = 0;
        char                 *real_path    = NULL;
        int32_t               _fd          = -1;
        struct cdp_fd      *pfd          = NULL;
        struct cdp_private *priv         = NULL;
        char                  was_present  = 1;
        gid_t                 gid          = 0;
        struct iatt           stbuf        = {0, };

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (this->private, out);
        VALIDATE_OR_GOTO (loc, out);
        VALIDATE_OR_GOTO (fd, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        op_ret = setgid_override (this, real_path, &gid);
        if (op_ret < 0) {
                op_errno = -op_ret;
                op_ret = -1;
                goto out;
        }

        SET_FS_ID (frame->root->uid, gid);

        if (priv->o_direct)
                flags |= O_DIRECT;

        op_ret = cdp_lstat_with_gfid (this, real_path, &stbuf, loc->inode->gfid);
        if ((op_ret == -1) && (errno == ENOENT)) {
                was_present = 0;
        }

        _fd = open (real_path, flags, 0);
        if (_fd == -1) {
                op_ret   = -1;
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "open on %s: %s", real_path, strerror (op_errno));
                goto out;
        }

        pfd = GF_CALLOC (1, sizeof (*pfd), gf_cdp_mt_cdp_fd);
        if (!pfd) {
                op_errno = errno;
                goto out;
        }

        pfd->flags = flags;
        pfd->fd    = _fd;
        if (wbflags == GF_OPEN_FSYNC)
                pfd->flushwrites = 1;

        op_ret = fd_ctx_set (fd, this, (uint64_t)(long)pfd);
        if (op_ret)
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to set the fd context path=%s fd=%p",
                        loc->path, fd);

#ifndef HAVE_SET_FSID
        if (flags & O_CREAT) {
                op_ret = chown (real_path, frame->root->uid, gid);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "chown on %s failed: %s",
                                real_path, strerror (op_errno));
                        goto out;
                }
        }
#endif

        if (flags & O_CREAT) {
                op_ret = cdp_lstat_with_gfid (this, real_path, &stbuf, loc->inode->gfid);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR, "lstat on (%s) "
                                "failed: %s", real_path, strerror (op_errno));
                        goto out;
                }
        }

        LOCK (&priv->lock);
        {
                priv->nr_files++;
        }
        UNLOCK (&priv->lock);

        op_ret = 0;

out:
        if (op_ret == -1) {
                if (_fd != -1) {
                        close (_fd);
                }
        }

        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (open, frame, op_ret, op_errno, fd);

        return 0;
}

#define ALIGN_BUF(ptr,bound) ((void *)((unsigned long)(ptr + bound - 1) & \
                                       (unsigned long)(~(bound - 1))))

int
cdp_readv (call_frame_t *frame, xlator_t *this,
             fd_t *fd, size_t size, off_t offset)
{
        uint64_t               tmp_pfd    = 0;
        int32_t                op_ret     = -1;
        int32_t                op_errno   = 0;
        int                    _fd        = -1;
        struct cdp_private * priv       = NULL;
        struct iobuf         * iobuf      = NULL;
        struct iobref        * iobref     = NULL;
        struct iovec           vec        = {0,};
        struct cdp_fd *      pfd        = NULL;
        struct iatt            stbuf      = {0,};
        int                    align      = 1;
        int                    ret        = -1;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);
        VALIDATE_OR_GOTO (this->private, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                op_errno = -ret;
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL from fd=%p", fd);
                goto out;
        }
        pfd = (struct cdp_fd *)(long)tmp_pfd;

        if (!size) {
                op_errno = EINVAL;
                gf_log (this->name, GF_LOG_WARNING, "size=%"GF_PRI_SIZET, size);
                goto out;
        }

        if (pfd->flags & O_DIRECT) {
                align = 4096;    /* align to page boundary */
        }

        iobuf = iobuf_get (this->ctx->iobuf_pool);
        if (!iobuf) {
                op_errno = ENOMEM;
                goto out;
        }

        _fd = pfd->fd;
        op_ret = pread (_fd, iobuf->ptr, size, offset);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "read failed on fd=%p: %s", fd,
                        strerror (op_errno));
                goto out;
        }

        LOCK (&priv->lock);
        {
                priv->read_value    += op_ret;
        }
        UNLOCK (&priv->lock);

        vec.iov_base = iobuf->ptr;
        vec.iov_len  = op_ret;

        iobref = iobref_new ();

        iobref_add (iobref, iobuf);

        /*
         *  readv successful, and we need to get the stat of the file
         *  we read from
         */

        op_ret = cdp_fstat_with_gfid (this, _fd, &stbuf, fd->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "fstat failed on fd=%p: %s", fd,
                        strerror (op_errno));
                goto out;
        }

        /* Hack to notify higher layers of EOF. */
        if (stbuf.ia_size == 0)
                op_errno = ENOENT;
        else if ((offset + vec.iov_len) == stbuf.ia_size)
                op_errno = ENOENT;
        else if (offset > stbuf.ia_size)
                op_errno = ENOENT;

        op_ret = vec.iov_len;
out:

        STACK_UNWIND_STRICT (readv, frame, op_ret, op_errno,
                             &vec, 1, &stbuf, iobref);

        if (iobref)
                iobref_unref (iobref);
        if (iobuf)
                iobuf_unref (iobuf);

        return 0;
}


int32_t
__cdp_pwritev (int fd, struct iovec *vector, int count, off_t offset)
{
        int32_t         op_ret = 0;
        int             idx = 0;
        int             retval = 0;
        off_t           internal_off = 0;

        if (!vector)
                return -EFAULT;

        internal_off = offset;
        for (idx = 0; idx < count; idx++) {
                retval = pwrite (fd, vector[idx].iov_base, vector[idx].iov_len,
                                 internal_off);
                if (retval == -1) {
                        op_ret = -errno;
                        goto err;
                }
                op_ret += retval;
                internal_off += retval;
        }

err:
        return op_ret;
}


int32_t
__cdp_writev (int fd, struct iovec *vector, int count, off_t startoff,
                int odirect)
{
        int32_t         op_ret = 0;
        int             idx = 0;
        int             align = 4096;
        int             max_buf_size = 0;
        int             retval = 0;
        char            *buf = NULL;
        char            *alloc_buf = NULL;
        off_t           internal_off = 0;

        /* Check for the O_DIRECT flag during open() */
        if (!odirect)
                return __cdp_pwritev (fd, vector, count, startoff);

        for (idx = 0; idx < count; idx++) {
                if (max_buf_size < vector[idx].iov_len)
                        max_buf_size = vector[idx].iov_len;
        }

        alloc_buf = GF_MALLOC (1 * (max_buf_size + align), gf_cdp_mt_char);
        if (!alloc_buf) {
                op_ret = -errno;
                goto err;
        }

        internal_off = startoff;
        for (idx = 0; idx < count; idx++) {
                /* page aligned buffer */
                buf = ALIGN_BUF (alloc_buf, align);

                memcpy (buf, vector[idx].iov_base, vector[idx].iov_len);

                /* not sure whether writev works on O_DIRECT'd fd */
                retval = pwrite (fd, buf, vector[idx].iov_len, internal_off);
                if (retval == -1) {
                        op_ret = -errno;
                        goto err;
                }

                op_ret += retval;
                internal_off += retval;
        }

err:
        if (alloc_buf)
                GF_FREE (alloc_buf);

        return op_ret;
}


int32_t
cdp_writev (call_frame_t *frame, xlator_t *this,
              fd_t *fd, struct iovec *vector, int32_t count, off_t offset,
              struct iobref *iobref)
{
        int32_t                op_ret   = -1;
        int32_t                op_errno = 0;
        int                    _fd      = -1;
        struct cdp_private * priv     = NULL;
        struct cdp_fd *      pfd      = NULL;
        struct iatt            preop    = {0,};
        struct iatt            postop    = {0,};
        int                      ret      = -1;

        uint64_t  tmp_pfd   = 0;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);
        VALIDATE_OR_GOTO (vector, out);
        VALIDATE_OR_GOTO (this->private, out);

        priv = this->private;

        VALIDATE_OR_GOTO (priv, out);

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL from fd=%p", fd);
                op_errno = -ret;
                goto out;
        }
        pfd = (struct cdp_fd *)(long)tmp_pfd;

        _fd = pfd->fd;

        op_ret = cdp_fstat_with_gfid (this, _fd, &preop, fd->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "pre-operation fstat failed on fd=%p: %s", fd,
                        strerror (op_errno));
                goto out;
        }

        op_ret = __cdp_writev (_fd, vector, count, offset,
                                 (pfd->flags & O_DIRECT));
        if (op_ret < 0) {
                op_errno = -op_ret;
                op_ret = -1;
                gf_log (this->name, GF_LOG_ERROR, "write failed: offset %"PRIu64
                        ", %s", offset, strerror (op_errno));
                goto out;
        }

        LOCK (&priv->lock);
        {
                priv->write_value    += op_ret;
        }
        UNLOCK (&priv->lock);

        if (op_ret >= 0) {
                /* wiretv successful, we also need to get the stat of
                 * the file we wrote to
                 */

                if (pfd->flushwrites) {
                        /* NOTE: ignore the error, if one occurs at this
                         * point */
                        fsync (_fd);
                }

                ret = cdp_fstat_with_gfid (this, _fd, &postop, fd->inode->gfid);
                if (ret == -1) {
                        op_ret = -1;
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "post-operation fstat failed on fd=%p: %s",
                                fd, strerror (op_errno));
                        goto out;
                }
        }

out:

        STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno, &preop, &postop);

        return 0;
}


int32_t
cdp_statfs (call_frame_t *frame, xlator_t *this,
              loc_t *loc)
{
        char *                 real_path = NULL;
        int32_t                op_ret    = -1;
        int32_t                op_errno  = 0;
        struct statvfs         buf       = {0, };
        struct cdp_private * priv      = NULL;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);
        VALIDATE_OR_GOTO (this->private, out);

        MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        priv = this->private;

        op_ret = statvfs (real_path, &buf);

        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "statvfs failed on %s: %s",
                        real_path, strerror (op_errno));
                goto out;
        }

        if (!priv->export_statfs) {
                buf.f_blocks = 0;
                buf.f_bfree  = 0;
                buf.f_bavail = 0;
                buf.f_files  = 0;
                buf.f_ffree  = 0;
                buf.f_favail = 0;
        }

        op_ret = 0;

out:
        STACK_UNWIND_STRICT (statfs, frame, op_ret, op_errno, &buf);
        return 0;
}


int32_t
cdp_flush (call_frame_t *frame, xlator_t *this,
             fd_t *fd)
{
        int32_t           op_ret   = -1;
        int32_t           op_errno = 0;
        struct cdp_fd * pfd      = NULL;
        int               ret      = -1;
        uint64_t          tmp_pfd  = 0;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                op_errno = -ret;
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL on fd=%p", fd);
                goto out;
        }
        pfd = (struct cdp_fd *)(long)tmp_pfd;

        op_ret = 0;

out:
        STACK_UNWIND_STRICT (flush, frame, op_ret, op_errno);

        return 0;
}


int32_t
cdp_release (xlator_t *this,
               fd_t *fd)
{
        struct cdp_private * priv     = NULL;
        struct cdp_fd *      pfd      = NULL;
        int                    ret      = -1;
        uint64_t               tmp_pfd  = 0;

        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        priv = this->private;

        ret = fd_ctx_del (fd, this, &tmp_pfd);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL from fd=%p", fd);
                goto out;
        }
        pfd = (struct cdp_fd *)(long)tmp_pfd;

        if (pfd->dir) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd->dir is %p (not NULL) for file fd=%p",
                        pfd->dir, fd);
        }

        close (pfd->fd);

        LOCK (&priv->lock);
        {
                priv->nr_files--;
        }
        UNLOCK (&priv->lock);

out:
        if (pfd) {
                if (pfd->path)
                        GF_FREE (pfd->path);

                GF_FREE (pfd);
        }

        return 0;
}


int32_t
cdp_fsync (call_frame_t *frame, xlator_t *this,
             fd_t *fd, int32_t datasync)
{
        int32_t           op_ret   = -1;
        int32_t           op_errno = 0;
        int               _fd      = -1;
        struct cdp_fd * pfd      = NULL;
        int               ret      = -1;
        uint64_t          tmp_pfd  = 0;
        struct iatt       preop = {0,};
        struct iatt       postop = {0,};

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        SET_FS_ID (frame->root->uid, frame->root->gid);

#ifdef GF_DARWIN_HOST_OS
        /* Always return success in case of fsync in MAC OS X */
        op_ret = 0;
        goto out;
#endif

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                op_errno = -ret;
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd not found in fd's ctx");
                goto out;
        }
        pfd = (struct cdp_fd *)(long)tmp_pfd;

        _fd = pfd->fd;

        op_ret = cdp_fstat_with_gfid (this, _fd, &preop, fd->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_WARNING,
                        "pre-operation fstat failed on fd=%p: %s", fd,
                        strerror (op_errno));
                goto out;
        }

        if (datasync) {
                ;
#ifdef HAVE_FDATASYNC
                op_ret = fdatasync (_fd);
                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "fdatasync on fd=%p failed: %s",
                                fd, strerror (errno));
                }
#endif
        } else {
                op_ret = fsync (_fd);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "fsync on fd=%p failed: %s",
                                fd, strerror (op_errno));
                        goto out;
                }
        }

        op_ret = cdp_fstat_with_gfid (this, _fd, &postop, fd->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_WARNING,
                        "post-operation fstat failed on fd=%p: %s", fd,
                        strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (fsync, frame, op_ret, op_errno, &preop, &postop);

        return 0;
}

static int gf_cdp_xattr_enotsup_log;

int32_t
cdp_setxattr (call_frame_t *frame, xlator_t *this,
                loc_t *loc, dict_t *dict, int flags)
{
        int32_t       op_ret                  = -1;
        int32_t       op_errno                = 0;
        char *        real_path               = NULL;
        data_pair_t * trav                    = NULL;
        int           ret                     = -1;

        DECLARE_OLD_FS_ID_VAR;
        SET_FS_ID (frame->root->uid, frame->root->gid);

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);
        VALIDATE_OR_GOTO (dict, out);

        MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        dict_del (dict, GFID_XATTR_KEY);

        trav = dict->members_list;

        while (trav) {
                ret = cdp_handle_pair (this, real_path, trav, flags);
                if (ret < 0) {
                        op_errno = -ret;
                        goto out;
                }
                trav = trav->next;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (setxattr, frame, op_ret, op_errno);

        return 0;
}

/**
 * cdp_getxattr - this function returns a dictionary with all the
 *                  key:value pair present as xattr. used for
 *                  both 'listxattr' and 'getxattr'.
 */
int32_t
cdp_getxattr (call_frame_t *frame, xlator_t *this,
                loc_t *loc, const char *name)
{
        struct cdp_private *priv  = NULL;
        int32_t  op_ret         = -1;
        int32_t  op_errno       = 0;
        int32_t  list_offset    = 0;
        size_t   size           = 0;
        size_t   remaining_size = 0;
        char     key[1024]      = {0,};
        char     host_buf[1024] = {0,};
        char *   value          = NULL;
        char *   list           = NULL;
        char *   real_path      = NULL;
        dict_t * dict           = NULL;
        char *   file_contents  = NULL;
        int      ret            = -1;

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);

        SET_FS_ID (frame->root->uid, frame->root->gid);
        MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        priv = this->private;

        if (loc->inode && IA_ISDIR(loc->inode->ia_type) && name &&
            ZR_FILE_CONTENT_REQUEST(name)) {
                ret = cdp_get_file_contents (this, real_path, name,
                                               &file_contents);
                if (ret < 0) {
                        op_errno = -ret;
                        gf_log (this->name, GF_LOG_ERROR,
                                "getting file contents failed: %s",
                                strerror (op_errno));
                        goto out;
                }
        }

        /* Get the total size */
        dict = get_new_dict ();
        if (!dict) {
                goto out;
        }

        if (loc->inode && name && !strcmp (name, GLUSTERFS_OPEN_FD_COUNT)) {
                if (!list_empty (&loc->inode->fd_list)) {
                        ret = dict_set_uint32 (dict, (char *)name, 1);
                        if (ret < 0)
                                gf_log (this->name, GF_LOG_WARNING,
                                        "Failed to set dictionary value for %s",
                                        name);
                } else {
                        ret = dict_set_uint32 (dict, (char *)name, 0);
                        if (ret < 0)
                                gf_log (this->name, GF_LOG_WARNING,
                                        "Failed to set dictionary value for %s",
                                        name);
                }
                goto done;
        }
        if (loc->inode && IA_ISREG (loc->inode->ia_type) && name &&
            (strcmp (name, GF_XATTR_PATHINFO_KEY) == 0)) {
                snprintf (host_buf, 1024, "<POSIX:%s:%s>", priv->hostname,
                          real_path);
                ret = dict_set_str (dict, GF_XATTR_PATHINFO_KEY,
                                    host_buf);
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "could not set value (%s) in dictionary",
                                host_buf);
                }
                goto done;
        }

        size = sys_llistxattr (real_path, NULL, 0);
        if (size == -1) {
                op_errno = errno;
                if ((errno == ENOTSUP) || (errno == ENOSYS)) {
                        GF_LOG_OCCASIONALLY (gf_cdp_xattr_enotsup_log,
                                             this->name, GF_LOG_WARNING,
                                             "Extended attributes not "
                                             "supported.");
                }
                else {
                        gf_log (this->name, GF_LOG_ERROR,
                                "listxattr failed on %s: %s",
                                real_path, strerror (op_errno));
                }
                goto out;
        }

        if (size == 0)
                goto done;

        list = alloca (size + 1);
        if (!list) {
                op_errno = errno;
                goto out;
        }

        size = sys_llistxattr (real_path, list, size);

        remaining_size = size;
        list_offset = 0;
        while (remaining_size > 0) {
                if (*(list + list_offset) == '\0')
                        break;

                strcpy (key, list + list_offset);
                op_ret = sys_lgetxattr (real_path, key, NULL, 0);
                if (op_ret == -1)
                        break;

                value = GF_CALLOC (op_ret + 1, sizeof(char),
                                   gf_cdp_mt_char);
                if (!value) {
                        op_errno = errno;
                        goto out;
                }

                op_ret = sys_lgetxattr (real_path, key, value, op_ret);
                if (op_ret == -1) {
                        op_errno = errno;
                        break;
                }

                value [op_ret] = '\0';
                dict_set (dict, key, data_from_dynptr (value, op_ret));

                remaining_size -= strlen (key) + 1;
                list_offset += strlen (key) + 1;

        } /* while (remaining_size > 0) */

done:
        op_ret = size;

        if (dict) {
                dict_del (dict, GFID_XATTR_KEY);
                dict_ref (dict);
        }

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (getxattr, frame, op_ret, op_errno, dict);

        if (dict)
                dict_unref (dict);

        return 0;
}


int32_t
cdp_fgetxattr (call_frame_t *frame, xlator_t *this,
                 fd_t *fd, const char *name)
{
        int32_t           op_ret         = -1;
        int32_t           op_errno       = ENOENT;
        uint64_t          tmp_pfd        = 0;
        struct cdp_fd * pfd            = NULL;
        int               _fd            = -1;
        int32_t           list_offset    = 0;
        size_t            size           = 0;
        size_t            remaining_size = 0;
        char              key[1024]      = {0,};
        char *            value          = NULL;
        char *            list           = NULL;
        dict_t *          dict           = NULL;
        int               ret            = -1;

        DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        SET_FS_ID (frame->root->uid, frame->root->gid);

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                op_errno = -ret;
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL from fd=%p", fd);
                goto out;
        }
        pfd = (struct cdp_fd *)(long)tmp_pfd;

        _fd = pfd->fd;

        /* Get the total size */
        dict = get_new_dict ();
        if (!dict) {
                goto out;
        }

        if (name && !strcmp (name, GLUSTERFS_OPEN_FD_COUNT)) {
                ret = dict_set_uint32 (dict, (char *)name, 1);
                if (ret < 0)
                        gf_log (this->name, GF_LOG_WARNING,
                                "Failed to set dictionary value for %s",
                                name);
                goto done;
        }

        size = sys_flistxattr (_fd, NULL, 0);
        if (size == -1) {
                op_errno = errno;
                if ((errno == ENOTSUP) || (errno == ENOSYS)) {
                        GF_LOG_OCCASIONALLY (gf_cdp_xattr_enotsup_log,
                                             this->name, GF_LOG_WARNING,
                                             "Extended attributes not "
                                             "supported.");
                }
                else {
                        gf_log (this->name, GF_LOG_ERROR,
                                "listxattr failed on %p: %s",
                                fd, strerror (op_errno));
                }
                goto out;
        }

        if (size == 0)
                goto done;

        list = alloca (size + 1);
        if (!list) {
                op_errno = errno;
                goto out;
        }

        size = sys_flistxattr (_fd, list, size);

        remaining_size = size;
        list_offset = 0;
        while (remaining_size > 0) {
                if(*(list + list_offset) == '\0')
                        break;

                strcpy (key, list + list_offset);
                op_ret = sys_fgetxattr (_fd, key, NULL, 0);
                if (op_ret == -1)
                        break;

                value = GF_CALLOC (op_ret + 1, sizeof(char),
                                   gf_cdp_mt_char);
                if (!value) {
                        op_errno = errno;
                        goto out;
                }

                op_ret = sys_fgetxattr (_fd, key, value, op_ret);
                if (op_ret == -1)
                        break;

                value [op_ret] = '\0';
                dict_set (dict, key, data_from_dynptr (value, op_ret));
                remaining_size -= strlen (key) + 1;
                list_offset += strlen (key) + 1;

        } /* while (remaining_size > 0) */

done:
        op_ret = size;

        if (dict) {
                dict_del (dict, GFID_XATTR_KEY);
                dict_ref (dict);
        }

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (fgetxattr, frame, op_ret, op_errno, dict);

        if (dict)
                dict_unref (dict);

        return 0;
}


int32_t
cdp_fsetxattr (call_frame_t *frame, xlator_t *this,
                 fd_t *fd, dict_t *dict, int flags)
{
        int32_t            op_ret       = -1;
        int32_t            op_errno     = 0;
        struct cdp_fd *  pfd          = NULL;
        uint64_t           tmp_pfd      = 0;
        int                _fd          = -1;
        data_pair_t * trav              = NULL;
        int           ret               = -1;

        DECLARE_OLD_FS_ID_VAR;
        SET_FS_ID (frame->root->uid, frame->root->gid);

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);
        VALIDATE_OR_GOTO (dict, out);

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                op_errno = -ret;
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL from fd=%p", fd);
                goto out;
        }
        pfd = (struct cdp_fd *)(long)tmp_pfd;
        _fd = pfd->fd;

        dict_del (dict, GFID_XATTR_KEY);

        trav = dict->members_list;

        while (trav) {
                ret = cdp_fhandle_pair (this, _fd, trav, flags);
                if (ret < 0) {
                        op_errno = -ret;
                        goto out;
                }
                trav = trav->next;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (fsetxattr, frame, op_ret, op_errno);

        return 0;
}


int32_t
cdp_removexattr (call_frame_t *frame, xlator_t *this,
                   loc_t *loc, const char *name)
{
        int32_t op_ret    = -1;
        int32_t op_errno  = 0;
        char *  real_path = NULL;

        DECLARE_OLD_FS_ID_VAR;

        if (!strcmp (GFID_XATTR_KEY, name)) {
                gf_log (this->name, GF_LOG_WARNING, "Remove xattr called"
                        " on gfid for file %s", loc->path);
                goto out;
        }

        MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        SET_FS_ID (frame->root->uid, frame->root->gid);

        op_ret = sys_lremovexattr (real_path, name);
        if (op_ret == -1) {
                op_errno = errno;
                if (op_errno != ENOATTR && op_errno != EPERM)
                        gf_log (this->name, GF_LOG_ERROR,
                                "removexattr on %s (for %s): %s", loc->path,
                                name, strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (removexattr, frame, op_ret, op_errno);
        return 0;
}


int32_t
cdp_fsyncdir (call_frame_t *frame, xlator_t *this,
                fd_t *fd, int datasync)
{
        int32_t           op_ret   = -1;
        int32_t           op_errno = 0;
        struct cdp_fd * pfd      = NULL;
        int               ret      = -1;
        uint64_t          tmp_pfd  = 0;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                op_errno = -ret;
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", fd);
                goto out;
        }
        pfd = (struct cdp_fd *)(long)tmp_pfd;

        op_ret = 0;

out:
        STACK_UNWIND_STRICT (fsyncdir, frame, op_ret, op_errno);

        return 0;
}


void
cdp_print_xattr (dict_t *this,
                   char *key,
                   data_t *value,
                   void *data)
{
        gf_log ("posix", GF_LOG_DEBUG,
                "(key/val) = (%s/%d)", key, data_to_int32 (value));
}


/**
 * add_array - add two arrays of 32-bit numbers (stored in network byte order)
 * dest = dest + src
 * @count: number of 32-bit numbers
 * FIXME: handle overflow
 */

static void
__add_array (int32_t *dest, int32_t *src, int count)
{
        int i = 0;
        for (i = 0; i < count; i++) {
                dest[i] = hton32 (ntoh32 (dest[i]) + ntoh32 (src[i]));
        }
}

static void
__add_long_array (int64_t *dest, int64_t *src, int count)
{
        int i = 0;
        for (i = 0; i < count; i++) {
                dest[i] = hton64 (ntoh64 (dest[i]) + ntoh64 (src[i]));
        }
}

/**
 * xattrop - xattr operations - for internal use by GlusterFS
 * @optype: ADD_ARRAY:
 *            dict should contain:
 *               "key" ==> array of 32-bit numbers
 */

int
do_xattrop (call_frame_t *frame, xlator_t *this,
            loc_t *loc, fd_t *fd, gf_xattrop_flags_t optype, dict_t *xattr)
{
        char            *real_path = NULL;
        char            *array = NULL;
        int              size = 0;
        int              count = 0;

        int              op_ret = 0;
        int              op_errno = 0;

        int              ret = 0;
        int              _fd = -1;
        uint64_t         tmp_pfd = 0;
        struct cdp_fd *pfd = NULL;

        data_pair_t     *trav = NULL;

        char *    path  = NULL;
        inode_t * inode = NULL;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (xattr, out);
        VALIDATE_OR_GOTO (this, out);

        trav = xattr->members_list;

        if (fd) {
                ret = fd_ctx_get (fd, this, &tmp_pfd);
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "failed to get pfd from fd=%p",
                                fd);
                        op_ret = -1;
                        op_errno = EBADFD;
                        goto out;
                }
                pfd = (struct cdp_fd *)(long)tmp_pfd;
                _fd = pfd->fd;
        }

        if (loc && loc->inode)
                MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        if (loc) {
                path  = gf_strdup (loc->path);
                inode = loc->inode;
        } else if (fd) {
                inode = fd->inode;
        }

        while (trav && inode) {
                count = trav->value->len;
                array = GF_CALLOC (count, sizeof (char),
                                   gf_cdp_mt_char);

                LOCK (&inode->lock);
                {
                        if (loc) {
                                size = sys_lgetxattr (real_path, trav->key, (char *)array,
                                                      trav->value->len);
                        } else {
                                size = sys_fgetxattr (_fd, trav->key, (char *)array,
                                                      trav->value->len);
                        }

                        op_errno = errno;
                        if ((size == -1) && (op_errno != ENODATA) &&
                            (op_errno != ENOATTR)) {
                                if (op_errno == ENOTSUP) {
                                        GF_LOG_OCCASIONALLY(gf_cdp_xattr_enotsup_log,
                                                            this->name,GF_LOG_WARNING,
                                                            "Extended attributes not "
                                                            "supported by filesystem");
                                } else  {
                                        if (loc)
                                                gf_log (this->name, GF_LOG_ERROR,
                                                        "getxattr failed on %s while doing "
                                                        "xattrop: %s", path,
                                                        strerror (op_errno));
                                        else
                                                gf_log (this->name, GF_LOG_ERROR,
                                                        "fgetxattr failed on fd=%d while doing "
                                                        "xattrop: %s", _fd,
                                                        strerror (op_errno));
                                }

                                op_ret = -1;
                                goto unlock;
                        }

                        switch (optype) {

                        case GF_XATTROP_ADD_ARRAY:
                                __add_array ((int32_t *) array, (int32_t *) trav->value->data,
                                             trav->value->len / 4);
                                break;

                        case GF_XATTROP_ADD_ARRAY64:
                                __add_long_array ((int64_t *) array, (int64_t *) trav->value->data,
                                                  trav->value->len / 8);
                                break;

                        default:
                                gf_log (this->name, GF_LOG_ERROR,
                                        "Unknown xattrop type (%d) on %s. Please send "
                                        "a bug report to gluster-devel@nongnu.org",
                                        optype, path);
                                op_ret = -1;
                                op_errno = EINVAL;
                                goto unlock;
                        }

                        if (loc) {
                                size = sys_lsetxattr (real_path, trav->key, array,
                                                      trav->value->len, 0);
                        } else {
                                size = sys_fsetxattr (_fd, trav->key, (char *)array,
                                                      trav->value->len, 0);
                        }
                }
        unlock:
                UNLOCK (&inode->lock);

                if (op_ret == -1)
                        goto out;

                op_errno = errno;
                if (size == -1) {
                        if (loc)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "setxattr failed on %s while doing xattrop: "
                                        "key=%s (%s)", path,
                                        trav->key, strerror (op_errno));
                        else
                                gf_log (this->name, GF_LOG_ERROR,
                                        "fsetxattr failed on fd=%d while doing xattrop: "
                                        "key=%s (%s)", _fd,
                                        trav->key, strerror (op_errno));

                        op_ret = -1;
                        goto out;
                } else {
                        size = dict_set_bin (xattr, trav->key, array,
                                             trav->value->len);

                        if (size != 0) {
                                if (loc)
                                        gf_log (this->name, GF_LOG_DEBUG,
                                                "dict_set_bin failed (path=%s): "
                                                "key=%s (%s)", path,
                                                trav->key, strerror (-size));
                                else
                                        gf_log (this->name, GF_LOG_DEBUG,
                                                "dict_set_bin failed (fd=%d): "
                                                "key=%s (%s)", _fd,
                                                trav->key, strerror (-size));

                                op_ret = -1;
                                op_errno = EINVAL;
                                goto out;
                        }
                        array = NULL;
                }

                array = NULL;
                trav = trav->next;
        }

out:
        if (array)
                GF_FREE (array);

        if (path)
                GF_FREE (path);

        STACK_UNWIND_STRICT (xattrop, frame, op_ret, op_errno, xattr);
        return 0;
}


int
cdp_xattrop (call_frame_t *frame, xlator_t *this,
               loc_t *loc, gf_xattrop_flags_t optype, dict_t *xattr)
{
        do_xattrop (frame, this, loc, NULL, optype, xattr);
        return 0;
}


int
cdp_fxattrop (call_frame_t *frame, xlator_t *this,
                fd_t *fd, gf_xattrop_flags_t optype, dict_t *xattr)
{
        do_xattrop (frame, this, NULL, fd, optype, xattr);
        return 0;
}


int
cdp_access (call_frame_t *frame, xlator_t *this,
              loc_t *loc, int32_t mask)
{
        int32_t                 op_ret    = -1;
        int32_t                 op_errno  = 0;
        char                   *real_path = NULL;

        DECLARE_OLD_FS_ID_VAR;
        SET_FS_ID (frame->root->uid, frame->root->gid);

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);

        MAKE_GFID_PATH (real_path, this, loc->inode->gfid);

        op_ret = access (real_path, mask & 07);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR, "access failed on %s: %s",
                        loc->path, strerror (op_errno));
                goto out;
        }
        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (access, frame, op_ret, op_errno);
        return 0;
}


int32_t
cdp_ftruncate (call_frame_t *frame, xlator_t *this,
                 fd_t *fd, off_t offset)
{
        int32_t               op_ret   = -1;
        int32_t               op_errno = 0;
        int                   _fd      = -1;
        struct iatt           preop    = {0,};
        struct iatt           postop   = {0,};
        struct cdp_fd      *pfd      = NULL;
        int                   ret      = -1;
        uint64_t              tmp_pfd  = 0;
        struct cdp_private *priv     = NULL;

        DECLARE_OLD_FS_ID_VAR;
        SET_FS_ID (frame->root->uid, frame->root->gid);

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", fd);
                op_errno = -ret;
                goto out;
        }
        pfd = (struct cdp_fd *)(long)tmp_pfd;

        _fd = pfd->fd;

        op_ret = cdp_fstat_with_gfid (this, _fd, &preop, fd->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "pre-operation fstat failed on fd=%p: %s", fd,
                        strerror (op_errno));
                goto out;
        }

        op_ret = ftruncate (_fd, offset);

        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "ftruncate failed on fd=%p: %s",
                        fd, strerror (errno));
                goto out;
        }

        op_ret = cdp_fstat_with_gfid (this, _fd, &postop, fd->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "post-operation fstat failed on fd=%p: %s",
                        fd, strerror (errno));
                goto out;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (ftruncate, frame, op_ret, op_errno, &preop, &postop);

        return 0;
}


int32_t
cdp_fstat (call_frame_t *frame, xlator_t *this,
             fd_t *fd)
{
        int                   _fd      = -1;
        int32_t               op_ret   = -1;
        int32_t               op_errno = 0;
        struct iatt           buf      = {0,};
        struct cdp_fd      *pfd      = NULL;
        uint64_t              tmp_pfd  = 0;
        int                   ret      = -1;
        struct cdp_private *priv     = NULL;

        DECLARE_OLD_FS_ID_VAR;
        SET_FS_ID (frame->root->uid, frame->root->gid);

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", fd);
                op_errno = -ret;
                goto out;
        }
        pfd = (struct cdp_fd *)(long)tmp_pfd;

        _fd = pfd->fd;

        op_ret = cdp_fstat_with_gfid (this, _fd, &buf, fd->inode->gfid);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR, "fstat failed on fd=%p: %s",
                        fd, strerror (op_errno));
                goto out;
        }

        op_ret = 0;

out:
        SET_TO_OLD_FS_ID ();

        STACK_UNWIND_STRICT (fstat, frame, op_ret, op_errno, &buf);
        return 0;
}

static int gf_cdp_lk_log;

int32_t
cdp_lk (call_frame_t *frame, xlator_t *this,
          fd_t *fd, int32_t cmd, struct gf_flock *lock)
{
        struct gf_flock nullock = {0, };

        GF_LOG_OCCASIONALLY (gf_cdp_lk_log, this->name, GF_LOG_CRITICAL,
                             "\"features/locks\" translator is "
                             "not loaded. You need to use it for proper "
                             "functioning of your application.");

        STACK_UNWIND_STRICT (lk, frame, -1, ENOSYS, &nullock);
        return 0;
}

int32_t
cdp_inodelk (call_frame_t *frame, xlator_t *this,
               const char *volume, loc_t *loc, int32_t cmd, struct gf_flock *lock)
{
        GF_LOG_OCCASIONALLY (gf_cdp_lk_log, this->name, GF_LOG_CRITICAL,
                             "\"features/locks\" translator is "
                             "not loaded. You need to use it for proper "
                             "functioning of your application.");

        STACK_UNWIND_STRICT (inodelk, frame, -1, ENOSYS);
        return 0;
}

int32_t
cdp_finodelk (call_frame_t *frame, xlator_t *this,
                const char *volume, fd_t *fd, int32_t cmd, struct gf_flock *lock)
{
        GF_LOG_OCCASIONALLY (gf_cdp_lk_log, this->name, GF_LOG_CRITICAL,
                             "\"features/locks\" translator is "
                             "not loaded. You need to use it for proper "
                             "functioning of your application.");

        STACK_UNWIND_STRICT (finodelk, frame, -1, ENOSYS);
        return 0;
}


int32_t
cdp_entrylk (call_frame_t *frame, xlator_t *this,
               const char *volume, loc_t *loc, const char *basename,
               entrylk_cmd cmd, entrylk_type type)
{
        GF_LOG_OCCASIONALLY (gf_cdp_lk_log, this->name, GF_LOG_CRITICAL,
                             "\"features/locks\" translator is "
                             "not loaded. You need to use it for proper "
                             "functioning of your application.");

        STACK_UNWIND_STRICT (entrylk, frame, -1, ENOSYS);
        return 0;
}

int32_t
cdp_fentrylk (call_frame_t *frame, xlator_t *this,
                const char *volume, fd_t *fd, const char *basename,
                entrylk_cmd cmd, entrylk_type type)
{
        GF_LOG_OCCASIONALLY (gf_cdp_lk_log, this->name, GF_LOG_CRITICAL,
                             "\"features/locks\" translator is "
                             "not loaded. You need to use it for proper "
                             "functioning of your application.");

        STACK_UNWIND_STRICT (fentrylk, frame, -1, ENOSYS);
        return 0;
}


int32_t
cdp_do_readdir (call_frame_t *frame, xlator_t *this,
                  fd_t *fd, size_t size, off_t off, int whichop)
{
        uint64_t              tmp_pfd        = 0;
        struct cdp_fd      *pfd            = NULL;
        DIR                  *dir            = NULL;
        int                   ret            = -1;
        size_t                filled         = 0;
        int                   count          = 0;
        int32_t               op_ret         = -1;
        int32_t               op_errno       = 0;
        gf_dirent_t          *this_entry     = NULL;
        gf_dirent_t           entries;
        struct dirent        *entry          = NULL;
        off_t                 in_case        = -1;
        int32_t               this_size      = -1;
        char                 *real_path      = NULL;
        int                   real_path_len  = -1;
        char                 *entry_path     = NULL;
        int                   entry_path_len = -1;
        struct cdp_private *priv           = NULL;
        struct iatt           stbuf          = {0, };
        char                  base_path[PATH_MAX] = {0,};
        gf_dirent_t          *tmp_entry      = NULL;
        struct stat           statbuf        = {0, };
        char                  hidden_path[PATH_MAX] = {0, };

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        INIT_LIST_HEAD (&entries.list);

        priv = this->private;

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", fd);
                op_errno = -ret;
                goto out;
        }
        pfd = (struct cdp_fd *)(long)tmp_pfd;
        if (!pfd->path) {
                op_errno = EBADFD;
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd does not have path set (possibly file "
                        "fd, fd=%p)", fd);
                goto out;
        }

        real_path     = pfd->path;
        real_path_len = strlen (real_path);

        entry_path_len = real_path_len + NAME_MAX;
        entry_path     = alloca (entry_path_len);

        strncpy(base_path, CDP_BASE_PATH(this), sizeof(base_path));
        base_path[strlen(base_path)] = '/';

        if (!entry_path) {
                op_errno = errno;
                goto out;
        }

        strncpy (entry_path, real_path, entry_path_len);
        entry_path[real_path_len] = '/';

        dir = pfd->dir;

        if (!dir) {
                gf_log (this->name, GF_LOG_WARNING,
                        "dir is NULL for fd=%p", fd);
                op_errno = EINVAL;
                goto out;
        }


        if (!off) {
                rewinddir (dir);
        } else {
                seekdir (dir, off);
        }

        while (filled <= size) {
                in_case = telldir (dir);

                if (in_case == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "telldir failed on dir=%p: %s",
                                dir, strerror (errno));
                        goto out;
                }

                errno = 0;
                entry = readdir (dir);

                if (!entry) {
                        if (errno == EBADF) {
                                op_errno = errno;
                                gf_log (this->name, GF_LOG_WARNING,
                                        "readdir failed on dir=%p: %s",
                                        dir, strerror (op_errno));
                                goto out;
                        }
                        break;
                }

                if ((!strcmp(real_path, base_path)) &&
                    (!strcmp(entry->d_name, GF_REPLICATE_TRASH_DIR)))
                        continue;

                if ((!strcmp (real_path, base_path))
                    && (!strncmp (GF_HIDDEN_PATH, entry->d_name,
                                  strlen(GF_HIDDEN_PATH)))) {
                        snprintf (hidden_path, PATH_MAX, "%s/%s", real_path,
                                  entry->d_name);
                        ret = lstat (hidden_path, &statbuf);
                        if (!ret && S_ISDIR (statbuf.st_mode))
                                continue;
                }
                this_size = max (sizeof (gf_dirent_t),
                                 sizeof (gfs3_dirplist))
                        + strlen (entry->d_name) + 1;

                if (this_size + filled > size) {
                        seekdir (dir, in_case);
                        break;
                }

                this_entry = gf_dirent_for_name (entry->d_name);

                if (!this_entry) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "could not create gf_dirent for entry %s: (%s)",
                                entry->d_name, strerror (errno));
                        goto out;
                }
                this_entry->d_off = telldir (dir);
                this_entry->d_ino = entry->d_ino;

                list_add_tail (&this_entry->list, &entries.list);

                filled += this_size;
                count ++;
        }

        if (whichop == GF_FOP_READDIRP) {
                list_for_each_entry (tmp_entry, &entries.list, list) {
                        strcpy (entry_path + real_path_len + 1,
                                tmp_entry->d_name);
                        cdp_lstat_with_gfid (this, entry_path, &stbuf, NULL);
                        if (stbuf.ia_ino)
                                tmp_entry->d_ino = stbuf.ia_ino;
                        tmp_entry->d_stat = stbuf;
                }
        }
        op_ret = count;
        errno = 0;
        if ((!readdir (dir) && (errno == 0)))
                op_errno = ENOENT;

out:
        STACK_UNWIND_STRICT (readdir, frame, op_ret, op_errno, &entries);

        gf_dirent_free (&entries);

        return 0;
}


int32_t
cdp_readdir (call_frame_t *frame, xlator_t *this,
               fd_t *fd, size_t size, off_t off)
{
        cdp_do_readdir (frame, this, fd, size, off, GF_FOP_READDIR);
        return 0;
}


int32_t
cdp_readdirp (call_frame_t *frame, xlator_t *this,
                fd_t *fd, size_t size, off_t off)
{
        cdp_do_readdir (frame, this, fd, size, off, GF_FOP_READDIRP);
        return 0;
}

int32_t
cdp_priv (xlator_t *this)
{
        struct cdp_private *priv = NULL;
        char  key_prefix[GF_DUMP_MAX_BUF_LEN];
        char  key[GF_DUMP_MAX_BUF_LEN];

        snprintf(key_prefix, GF_DUMP_MAX_BUF_LEN, "%s.%s", this->type,
                 this->name);
        gf_proc_dump_add_section(key_prefix);

        if (!this)
                return 0;

        priv = this->private;

        if (!priv)
                return 0;

        gf_proc_dump_build_key(key, key_prefix, "base_path");
        gf_proc_dump_write(key,"%s", priv->base_path);
        gf_proc_dump_build_key(key, key_prefix, "base_path_length");
        gf_proc_dump_write(key,"%d", priv->base_path_length);
        gf_proc_dump_build_key(key, key_prefix, "max_read");
        gf_proc_dump_write(key,"%d", priv->read_value);
        gf_proc_dump_build_key(key, key_prefix, "max_write");
        gf_proc_dump_write(key,"%d", priv->write_value);
        gf_proc_dump_build_key(key, key_prefix, "nr_files");
        gf_proc_dump_write(key,"%ld", priv->nr_files);

        return 0;
}

int32_t
cdp_inode (xlator_t *this)
{
        return 0;
}


int32_t
cdp_rchecksum (call_frame_t *frame, xlator_t *this,
                 fd_t *fd, off_t offset, int32_t len)
{
        char *buf = NULL;

        int       _fd      = -1;
        uint64_t  tmp_pfd  =  0;

        struct cdp_fd *pfd  = NULL;

        int op_ret   = -1;
        int op_errno = 0;

        int ret = 0;

        int32_t weak_checksum = 0;
        uint8_t strong_checksum[MD5_DIGEST_LEN];

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        memset (strong_checksum, 0, MD5_DIGEST_LEN);
        buf = GF_CALLOC (1, len, gf_cdp_mt_char);

        if (!buf) {
                op_errno = ENOMEM;
                goto out;
        }

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", fd);
                op_errno = -ret;
                goto out;
        }
        pfd = (struct cdp_fd *)(long) tmp_pfd;

        _fd = pfd->fd;

        ret = pread (_fd, buf, len, offset);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pread of %d bytes returned %d (%s)",
                        len, ret, strerror (errno));

                op_errno = errno;
                goto out;
        }

        weak_checksum = gf_rsync_weak_checksum (buf, len);
        gf_rsync_strong_checksum (buf, len, strong_checksum);

        GF_FREE (buf);

        op_ret = 0;
out:
        STACK_UNWIND_STRICT (rchecksum, frame, op_ret, op_errno,
                             weak_checksum, strong_checksum);
        return 0;
}


/**
 * notify - when parent sends PARENT_UP, send CHILD_UP event from here
 */
int32_t
notify (xlator_t *this,
        int32_t event,
        void *data,
        ...)
{
        switch (event)
        {
        case GF_EVENT_PARENT_UP:
        {
                /* Tell the parent that posix xlator is up */
                default_notify (this, GF_EVENT_CHILD_UP, data);
        }
        break;
        default:
                /* */
                break;
        }
        return 0;
}

int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        if (!this)
                return ret;

        ret = xlator_mem_acct_init (this, gf_cdp_mt_end + 1);

        if (ret != 0) {
                gf_log(this->name, GF_LOG_ERROR, "Memory accounting init"
                       "failed");
                return ret;
        }

        return ret;
}

/**
 * init -
 */
int
init (xlator_t *this)
{
        struct cdp_private  *_private      = NULL;
        data_t                *dir_data      = NULL;
        data_t                *tmp_data      = NULL;
        struct stat            buf           = {0,};
        gf_boolean_t           tmp_bool      = 0;
        int                    ret           = 0;
        int                    op_ret        = -1;
        uuid_t                 old_uuid;
        uuid_t                 dict_uuid;
        uuid_t                 root_gfid = {0,};

        dir_data = dict_get (this->options, "directory");

        if (this->children) {
                gf_log (this->name, GF_LOG_CRITICAL,
                        "FATAL: storage/posix cannot have subvolumes");
                ret = -1;
                goto out;
        }

        if (!this->parents) {
                gf_log (this->name, GF_LOG_WARNING,
                        "Volume is dangling. Please check the volume file.");
        }

        if (!dir_data) {
                gf_log (this->name, GF_LOG_CRITICAL,
                        "Export directory not specified in volume file.");
                ret = -1;
                goto out;
        }

        umask (000); // umask `masking' is done at the client side

        /* Check whether the specified directory exists, if not log it. */
        op_ret = stat (dir_data->data, &buf);
        if ((op_ret != 0) || !S_ISDIR (buf.st_mode)) {
                gf_log (this->name, GF_LOG_ERROR,
                        "Directory '%s' doesn't exist, exiting.",
                        dir_data->data);
                ret = -1;
                goto out;
        }

        /* Check for Extended attribute support, if not present, log it */
        op_ret = sys_lsetxattr (dir_data->data,
                                "trusted.glusterfs.test", "working", 8, 0);
        if (op_ret == 0) {
                sys_lremovexattr (dir_data->data, "trusted.glusterfs.test");
        } else {
                tmp_data = dict_get (this->options,
                                     "mandate-attribute");
                if (tmp_data) {
                        if (gf_string2boolean (tmp_data->data,
                                               &tmp_bool) == -1) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "wrong option provided for key "
                                        "\"mandate-attribute\"");
                                ret = -1;
                                goto out;
                        }
                        if (!tmp_bool) {
                                gf_log (this->name, GF_LOG_WARNING,
                                        "Extended attribute not supported, "
                                        "starting as per option");
                        } else {
                                gf_log (this->name, GF_LOG_CRITICAL,
                                        "Extended attribute not supported, "
                                        "exiting.");
                                ret = -1;
                                goto out;
                        }
                } else {
                        gf_log (this->name, GF_LOG_CRITICAL,
                                "Extended attribute not supported, exiting.");
                        ret = -1;
                        goto out;
                }
        }

        tmp_data = dict_get (this->options, "volume-id");
        if (tmp_data) {
                op_ret = uuid_parse (tmp_data->data, dict_uuid);
                if (op_ret < 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "wrong volume-id (%s) set in volume file",
                                tmp_data->data);
                        ret = -1;
                        goto out;
                }
                op_ret = sys_lgetxattr (dir_data->data,
                                        "trusted.glusterfs.volume-id", old_uuid, 16);
                if (op_ret == 16) {
                        if (uuid_compare (old_uuid, dict_uuid)) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "mismatching volume-id (%s) recieved. "
                                        "already is a part of volume %s ",
                                        tmp_data->data, uuid_utoa (old_uuid));
                                ret = -1;
                                goto out;
                        }
                } else if (op_ret == -1) {
                        /* Using the export for first time */
                        op_ret = sys_lsetxattr (dir_data->data,
                                                "trusted.glusterfs.volume-id",
                                                dict_uuid, 16, 0);
                        if (op_ret == -1) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to set volume id on export");
                                ret = -1;
                                goto out;
                        }
                } else {
                        ret = -1;
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to fetch volume id from export");
                        goto out;
                }
        }

        op_ret = sys_lgetxattr (dir_data->data, "system.cdp_acl_access",
                                NULL, 0);
        if ((op_ret < 0) && (errno == ENOTSUP))
                gf_log (this->name, GF_LOG_WARNING,
                        "Posix access control list is not supported.");

        _private = GF_CALLOC (1, sizeof (*_private),
                              gf_cdp_mt_cdp_private);
        if (!_private) {
                ret = -1;
                goto out;
        }

        _private->base_path = gf_strdup (dir_data->data);
        _private->base_path_length = strlen (_private->base_path);

        _private->trash_path = GF_CALLOC (1, _private->base_path_length
                                          + strlen ("/")
                                          + strlen (GF_REPLICATE_TRASH_DIR)
                                          + 1,
                                          gf_cdp_mt_trash_path);

        if (!_private->trash_path) {
                ret = -1;
                goto out;
        }

        strncpy (_private->trash_path, _private->base_path, _private->base_path_length);
        strcat (_private->trash_path, "/" GF_REPLICATE_TRASH_DIR);

        LOCK_INIT (&_private->lock);

        ret = dict_get_str (this->options, "hostname", &_private->hostname);
        if (ret) {
                _private->hostname = GF_CALLOC (256, sizeof (char),
                                                gf_common_mt_char);
                if (!_private->hostname) {
                        goto out;
                }
                ret = gethostname (_private->hostname, 256);
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "could not find hostname (%s)", strerror (errno));
                }
        }

        _private->export_statfs = 1;
        tmp_data = dict_get (this->options, "export-statfs-size");
        if (tmp_data) {
                if (gf_string2boolean (tmp_data->data,
                                       &_private->export_statfs) == -1) {
                        ret = -1;
                        gf_log (this->name, GF_LOG_ERROR,
                                "'export-statfs-size' takes only boolean "
                                "options");
                        goto out;
                }
                if (!_private->export_statfs)
                        gf_log (this->name, GF_LOG_DEBUG,
                                "'statfs()' returns dummy size");
        }

        tmp_data = dict_get (this->options, "o-direct");
        if (tmp_data) {
                if (gf_string2boolean (tmp_data->data,
                                       &_private->o_direct) == -1) {
                        ret = -1;
                        gf_log (this->name, GF_LOG_ERROR,
                                "wrong option provided for 'o-direct'");
                        goto out;
                }
                if (_private->o_direct)
                        gf_log (this->name, GF_LOG_DEBUG,
                                "o-direct mode is enabled (O_DIRECT "
                                "for every open)");
        }

#ifndef GF_DARWIN_HOST_OS
        {
                struct rlimit lim;
                lim.rlim_cur = 1048576;
                lim.rlim_max = 1048576;

                if (setrlimit (RLIMIT_NOFILE, &lim) == -1) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "Failed to set 'ulimit -n "
                                " 1048576': %s", strerror(errno));
                        lim.rlim_cur = 65536;
                        lim.rlim_max = 65536;

                        if (setrlimit (RLIMIT_NOFILE, &lim) == -1) {
                                gf_log (this->name, GF_LOG_WARNING,
                                        "Failed to set maximum allowed open "
                                        "file descriptors to 64k: %s",
                                        strerror(errno));
                        }
                        else {
                                gf_log (this->name, GF_LOG_INFO,
                                        "Maximum allowed open file descriptors "
                                        "set to 65536");
                        }
                }
        }
#endif
        this->private = (void *)_private;

        /* wanted 'this->private' to be set before this */
        root_gfid[15] = 1;
        ret = create_gfid_directory_path (this, root_gfid, S_IFDIR | 0777);
        if ((ret == -1) && (errno != EEXIST))
                goto out;

        ret = 0;
out:
        return ret;
}

void
fini (xlator_t *this)
{
        struct cdp_private *priv = this->private;
        if (!priv)
                return;
        this->private = NULL;
        GF_FREE (priv);
        return;
}

struct xlator_dumpops dumpops = {
        .priv    = cdp_priv,
        .inode   = cdp_inode,
};

struct xlator_fops fops = {
        .lookup      = cdp_lookup,
        .stat        = cdp_stat,
        .opendir     = cdp_opendir,
        .readdir     = cdp_readdir,
        .readdirp    = cdp_readdirp,
        .readlink    = cdp_readlink,
        .mknod       = cdp_mknod,
        .mkdir       = cdp_mkdir,
        .unlink      = cdp_unlink,
        .rmdir       = cdp_rmdir,
        .symlink     = cdp_symlink,
        .rename      = cdp_rename,
        .link        = cdp_link,
        .truncate    = cdp_truncate,
        .create      = cdp_create,
        .open        = cdp_open,
        .readv       = cdp_readv,
        .writev      = cdp_writev,
        .statfs      = cdp_statfs,
        .flush       = cdp_flush,
        .fsync       = cdp_fsync,
        .setxattr    = cdp_setxattr,
        .fsetxattr   = cdp_fsetxattr,
        .getxattr    = cdp_getxattr,
        .fgetxattr   = cdp_fgetxattr,
        .removexattr = cdp_removexattr,
        .fsyncdir    = cdp_fsyncdir,
        .access      = cdp_access,
        .ftruncate   = cdp_ftruncate,
        .fstat       = cdp_fstat,
        .lk          = cdp_lk,
        .inodelk     = cdp_inodelk,
        .finodelk    = cdp_finodelk,
        .entrylk     = cdp_entrylk,
        .fentrylk    = cdp_fentrylk,
        .rchecksum   = cdp_rchecksum,
        .xattrop     = cdp_xattrop,
        .fxattrop    = cdp_fxattrop,
        .setattr     = cdp_setattr,
        .fsetattr    = cdp_fsetattr,
};

struct xlator_cbks cbks = {
        .release     = cdp_release,
        .releasedir  = cdp_releasedir,
        .forget      = cdp_forget
};

struct volume_options options[] = {
        { .key  = {"o-direct"},
          .type = GF_OPTION_TYPE_BOOL },
        { .key  = {"directory"},
          .type = GF_OPTION_TYPE_PATH },
        { .key  = {"hostname"},
          .type = GF_OPTION_TYPE_ANY },
        { .key  = {"export-statfs-size"},
          .type = GF_OPTION_TYPE_BOOL },
        { .key  = {"mandate-attribute"},
          .type = GF_OPTION_TYPE_BOOL },
        { .key  = {NULL} }
};
