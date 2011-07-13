/*
  Copyright (c) 2006-2011 Gluster, Inc. <http://www.gluster.com>
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


typedef struct {
        xlator_t    *this;
        const char  *real_path;
        dict_t      *xattr;
        struct iatt *stbuf;
        loc_t       *loc;
} cdp_xattr_filler_t;


static void
_cdp_xattr_get_set (dict_t *xattr_req,
                      char *key,
                      data_t *data,
                      void *xattrargs)
{
        cdp_xattr_filler_t *filler = xattrargs;
        char     *value      = NULL;
        ssize_t   xattr_size = -1;
        int       ret      = -1;
        char     *databuf  = NULL;
        int       _fd      = -1;
        loc_t    *loc      = NULL;
        ssize_t  req_size  = 0;


        if (!strcmp (key, "gfid-req"))
                return;
        /* should size be put into the data_t ? */
        if (!strcmp (key, GF_CONTENT_KEY)
            && IA_ISREG (filler->stbuf->ia_type)) {

                /* file content request */
                req_size = data_to_uint64 (data);
                if (req_size >= filler->stbuf->ia_size) {
                        _fd = open (filler->real_path, O_RDONLY);
                        if (_fd == -1) {
                                gf_log (filler->this->name, GF_LOG_ERROR,
                                        "Opening file %s failed: %s",
                                        filler->real_path, strerror (errno));
                                goto err;
                        }

                        databuf = GF_CALLOC (1, filler->stbuf->ia_size,
                                             gf_cdp_mt_char);
                        if (!databuf) {
                                goto err;
                        }

                        ret = read (_fd, databuf, filler->stbuf->ia_size);
                        if (ret == -1) {
                                gf_log (filler->this->name, GF_LOG_ERROR,
                                        "Read on file %s failed: %s",
                                        filler->real_path, strerror (errno));
                                goto err;
                        }

                        ret = close (_fd);
                        _fd = -1;
                        if (ret == -1) {
                                gf_log (filler->this->name, GF_LOG_ERROR,
                                        "Close on file %s failed: %s",
                                        filler->real_path, strerror (errno));
                                goto err;
                        }

                        ret = dict_set_bin (filler->xattr, key,
                                            databuf, filler->stbuf->ia_size);
                        if (ret < 0) {
                                gf_log (filler->this->name, GF_LOG_ERROR,
                                        "failed to set dict value. key: %s, path: %s",
                                        key, filler->real_path);
                                goto err;
                        }

                        /* To avoid double free in cleanup below */
                        databuf = NULL;
                err:
                        if (_fd != -1)
                                close (_fd);
                        if (databuf)
                                GF_FREE (databuf);
                }
        } else if (!strcmp (key, GLUSTERFS_OPEN_FD_COUNT)) {
                loc = filler->loc;
                if (!list_empty (&loc->inode->fd_list)) {
                        ret = dict_set_uint32 (filler->xattr, key, 1);
                        if (ret < 0)
                                gf_log (filler->this->name, GF_LOG_WARNING,
                                        "Failed to set dictionary value for %s",
                                        key);
                } else {
                        ret = dict_set_uint32 (filler->xattr, key, 0);
                        if (ret < 0)
                                gf_log (filler->this->name, GF_LOG_WARNING,
                                        "Failed to set dictionary value for %s",
                                        key);
                }
        } else {
                xattr_size = sys_lgetxattr (filler->real_path, key, NULL, 0);

                if (xattr_size > 0) {
                        value = GF_CALLOC (1, xattr_size + 1,
                                           gf_cdp_mt_char);
                        if (!value)
                                return;

                        sys_lgetxattr (filler->real_path, key, value,
                                       xattr_size);

                        value[xattr_size] = '\0';
                        ret = dict_set_bin (filler->xattr, key,
                                            value, xattr_size);
                        if (ret < 0)
                                gf_log (filler->this->name, GF_LOG_DEBUG,
                                        "dict set failed. path: %s, key: %s",
                                        filler->real_path, key);
                }
        }
}


int
cdp_fill_gfid_path (xlator_t *this, const char *path, struct iatt *iatt)
{
        int ret = 0;

        if (!iatt)
                return 0;

        ret = sys_lgetxattr (path, GFID_XATTR_KEY, iatt->ia_gfid, 16);
        /* Return value of getxattr */
        if (ret == 16)
                ret = 0;

        return ret;
}


int
cdp_fill_gfid_fd (xlator_t *this, int fd, struct iatt *iatt)
{
        int ret = 0;

        if (!iatt)
                return 0;

        ret = sys_fgetxattr (fd, GFID_XATTR_KEY, iatt->ia_gfid, 16);
        /* Return value of getxattr */
        if (ret == 16)
                ret = 0;

        return ret;
}

void
cdp_fill_ino_from_gfid (xlator_t *this, struct iatt *buf)
{
        uint64_t temp_ino = 0;
        int j = 0;
        int i = 0;

        /* consider least significant 8 bytes of value out of gfid */
        for (i = 15; i > (15 - 8); i--) {
                temp_ino += buf->ia_gfid[i] << j;
                j += 8;
        }

        buf->ia_ino = temp_ino;
}

int
cdp_lstat_with_gfid (xlator_t *this, const char *path, struct iatt *stbuf_p,
                       uuid_t gfid)
{
        struct cdp_private  *priv    = NULL;
        int                    ret     = 0;
        struct stat            lstatbuf = {0, };
        struct iatt            stbuf = {0, };

        priv = this->private;

        ret = lstat (path, &lstatbuf);
        if (ret == -1)
                goto out;

        iatt_from_stat (&stbuf, &lstatbuf);

        if (!IA_ISDIR(stbuf.ia_type))
                stbuf.ia_nlink--;

        if (gfid) {
                uuid_copy (stbuf.ia_gfid, gfid);
                cdp_fill_ino_from_gfid (this, &stbuf);
        }

        if (stbuf_p)
                *stbuf_p = stbuf;
out:
        return ret;
}


int
cdp_fstat_with_gfid (xlator_t *this, int fd, struct iatt *stbuf_p, uuid_t gfid)
{
        struct cdp_private  *priv    = NULL;
        int                    ret     = 0;
        struct stat            fstatbuf = {0, };
        struct iatt            stbuf = {0, };

        priv = this->private;

        ret = fstat (fd, &fstatbuf);
        if (ret == -1)
                goto out;

        iatt_from_stat (&stbuf, &fstatbuf);

        if (!IA_ISDIR(stbuf.ia_type))
                stbuf.ia_nlink--;

        if (gfid) {
                uuid_copy (stbuf.ia_gfid, gfid);
                cdp_fill_ino_from_gfid (this, &stbuf);
        }

        if (stbuf_p)
                *stbuf_p = stbuf;

out:
        return ret;
}


dict_t *
cdp_lookup_xattr_fill (xlator_t *this, const char *real_path, loc_t *loc,
                         dict_t *xattr_req, struct iatt *buf)
{
        dict_t     *xattr             = NULL;
        cdp_xattr_filler_t filler   = {0, };

        xattr = get_new_dict();
        if (!xattr) {
                goto out;
        }

        filler.this      = this;
        filler.real_path = real_path;
        filler.xattr     = xattr;
        filler.stbuf     = buf;
        filler.loc       = loc;

        dict_foreach (xattr_req, _cdp_xattr_get_set, &filler);
out:
        return xattr;
}


/*
 * If the parent directory of {real_path} has the setgid bit set,
 * then set {gid} to the gid of the parent. Otherwise,
 * leave {gid} unchanged.
 */

int
setgid_override (xlator_t *this, char *path, gid_t *gid)
{
        struct iatt stbuf;
        int op_ret = 0;

        op_ret = cdp_lstat_with_gfid (this, path, &stbuf, NULL);
        if (op_ret == -1) {
                op_ret = -errno;
                gf_log_callingfn (this->name, GF_LOG_ERROR,
                                  "lstat on parent directory (%s) failed: %s",
                                  path, strerror (errno));
                goto out;
        }

        if (stbuf.ia_prot.sgid) {
                /*
                 * Entries created inside a setgid directory
                 * should inherit the gid from the parent
                 */

                *gid = stbuf.ia_gid;
        }

out:
        return op_ret;
}


int
cdp_gfid_set (xlator_t *this, const char *path, dict_t *xattr_req,
              uuid_t gfid)
{
        void        *uuid_req = NULL;
        int          ret = 0;
        struct stat  stat = {0, };

        if (!xattr_req)
                goto out;

        if (sys_lstat (path, &stat) != 0)
                goto out;

        ret = sys_lgetxattr (path, GFID_XATTR_KEY, gfid, 16);
        if (ret == 16) {
                ret = 0;
                goto out;
        }

        ret = dict_get_ptr (xattr_req, "gfid-req", &uuid_req);
        if (ret) {
                gf_log_callingfn (this->name, GF_LOG_DEBUG,
                                  "failed to get the gfid from dict");
                goto out;
        }

        ret = sys_lsetxattr (path, GFID_XATTR_KEY, uuid_req, 16, XATTR_CREATE);

        if (!ret)
                uuid_copy (gfid, uuid_req);

out:
        return ret;
}


int
cdp_set_file_contents (xlator_t *this, const char *real_path,
                         data_pair_t *trav, int flags)
{
        char *      key                        = NULL;
        char        real_filepath[ZR_PATH_MAX] = {0,};
        int32_t     file_fd                    = -1;
        int         op_ret                     = 0;
        int         ret                        = -1;

        key = &(trav->key[15]);
        sprintf (real_filepath, "%s/%s", real_path, key);

        if (flags & XATTR_REPLACE) {
                /* if file exists, replace it
                 * else, error out */
                file_fd = open (real_filepath, O_TRUNC|O_WRONLY);

                if (file_fd == -1) {
                        goto create;
                }

                if (trav->value->len) {
                        ret = write (file_fd, trav->value->data,
                                     trav->value->len);
                        if (ret == -1) {
                                op_ret = -errno;
                                gf_log (this->name, GF_LOG_ERROR,
                                        "write failed while doing setxattr "
                                        "for key %s on path %s: %s",
                                        key, real_filepath, strerror (errno));
                                goto out;
                        }

                        ret = close (file_fd);
                        if (ret == -1) {
                                op_ret = -errno;
                                gf_log (this->name, GF_LOG_ERROR,
                                        "close failed on %s: %s",
                                        real_filepath, strerror (errno));
                                goto out;
                        }
                }

        create: /* we know file doesn't exist, create it */

                file_fd = open (real_filepath, O_CREAT|O_WRONLY, 0644);

                if (file_fd == -1) {
                        op_ret = -errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to open file %s with O_CREAT: %s",
                                key, strerror (errno));
                        goto out;
                }

                ret = write (file_fd, trav->value->data, trav->value->len);
                if (ret == -1) {
                        op_ret = -errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "write failed on %s while setxattr with "
                                "key %s: %s",
                                real_filepath, key, strerror (errno));
                        goto out;
                }

                ret = close (file_fd);
                if (ret == -1) {
                        op_ret = -errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "close failed on %s while setxattr with "
                                "key %s: %s",
                                real_filepath, key, strerror (errno));
                        goto out;
                }
        }

out:
        return op_ret;
}


int
cdp_get_file_contents (xlator_t *this, const char *real_path,
                         const char *name, char **contents)
{
        char        real_filepath[ZR_PATH_MAX] = {0,};
        char *      key                        = NULL;
        int32_t     file_fd                    = -1;
        struct iatt stbuf                      = {0,};
        int         op_ret                     = 0;
        int         ret                        = -1;

        key = (char *) &(name[15]);
        sprintf (real_filepath, "%s/%s", real_path, key);

        op_ret = cdp_lstat_with_gfid (this, real_filepath, &stbuf, NULL);
        if (op_ret == -1) {
                op_ret = -errno;
                gf_log (this->name, GF_LOG_ERROR, "lstat failed on %s: %s",
                        real_filepath, strerror (errno));
                goto out;
        }

        file_fd = open (real_filepath, O_RDONLY);

        if (file_fd == -1) {
                op_ret = -errno;
                gf_log (this->name, GF_LOG_ERROR, "open failed on %s: %s",
                        real_filepath, strerror (errno));
                goto out;
        }

        *contents = GF_CALLOC (stbuf.ia_size + 1, sizeof(char),
                               gf_cdp_mt_char);
        if (! *contents) {
                op_ret = -errno;
                goto out;
        }

        ret = read (file_fd, *contents, stbuf.ia_size);
        if (ret <= 0) {
                op_ret = -1;
                gf_log (this->name, GF_LOG_ERROR, "read on %s failed: %s",
                        real_filepath, strerror (errno));
                goto out;
        }

        *contents[stbuf.ia_size] = '\0';

        op_ret = close (file_fd);
        file_fd = -1;
        if (op_ret == -1) {
                op_ret = -errno;
                gf_log (this->name, GF_LOG_ERROR, "close on %s failed: %s",
                        real_filepath, strerror (errno));
                goto out;
        }

out:
        if (op_ret < 0) {
                if (*contents)
                        GF_FREE (*contents);
                if (file_fd != -1)
                        close (file_fd);
        }

        return op_ret;
}

static int gf_xattr_enotsup_log;

int
cdp_handle_pair (xlator_t *this, const char *real_path,
                   data_pair_t *trav, int flags)
{
        int sys_ret = -1;
        int ret     = 0;

        if (ZR_FILE_CONTENT_REQUEST(trav->key)) {
                ret = cdp_set_file_contents (this, real_path, trav, flags);
        } else {
                sys_ret = sys_lsetxattr (real_path, trav->key,
                                         trav->value->data,
                                         trav->value->len, flags);

                if (sys_ret < 0) {
                        if (errno == ENOTSUP) {
                                GF_LOG_OCCASIONALLY(gf_xattr_enotsup_log,
                                                    this->name,GF_LOG_WARNING,
                                                    "Extended attributes not "
                                                    "supported");
                        } else if (errno == ENOENT) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "setxattr on %s failed: %s", real_path,
                                        strerror (errno));
                        } else {

#ifdef GF_DARWIN_HOST_OS
                                gf_log (this->name,
                                        ((errno == EINVAL) ?
                                         GF_LOG_DEBUG : GF_LOG_ERROR),
                                        "%s: key:%s error:%s",
                                        real_path, trav->key,
                                        strerror (errno));
#else /* ! DARWIN */
                                gf_log (this->name, GF_LOG_ERROR,
                                        "%s: key:%s error:%s",
                                        real_path, trav->key,
                                        strerror (errno));
#endif /* DARWIN */
                        }

                        ret = -errno;
                        goto out;
                }
        }
out:
        return ret;
}

int
cdp_fhandle_pair (xlator_t *this, int fd,
                    data_pair_t *trav, int flags)
{
        int sys_ret = -1;
        int ret     = 0;

        sys_ret = sys_fsetxattr (fd, trav->key, trav->value->data,
                                 trav->value->len, flags);

        if (sys_ret < 0) {
                if (errno == ENOTSUP) {
                        GF_LOG_OCCASIONALLY(gf_xattr_enotsup_log,
                                            this->name,GF_LOG_WARNING,
                                            "Extended attributes not "
                                            "supported");
                } else if (errno == ENOENT) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "fsetxattr on fd=%d failed: %s", fd,
                                strerror (errno));
                } else {

#ifdef GF_DARWIN_HOST_OS
                        gf_log (this->name,
                                ((errno == EINVAL) ?
                                 GF_LOG_DEBUG : GF_LOG_ERROR),
                                "fd=%d: key:%s error:%s",
                                fd, trav->key,
                                strerror (errno));
#else /* ! DARWIN */
                        gf_log (this->name, GF_LOG_ERROR,
                                "fd=%d: key:%s error:%s",
                                fd, trav->key,
                                strerror (errno));
#endif /* DARWIN */
                }

                ret = -errno;
                goto out;
        }

out:
        return ret;
}

int
cdp_acl_xattr_set (xlator_t *this, const char *path, dict_t *xattr_req)
{
        int          ret = 0;
        data_t      *data = NULL;
        struct stat  stat = {0, };

        if (!xattr_req)
                goto out;

        if (sys_lstat (path, &stat) != 0)
                goto out;

        data = dict_get (xattr_req, "system.cdp_acl_access");
        if (data) {
                ret = sys_lsetxattr (path, "system.cdp_acl_access",
                                     data->data, data->len, 0);
                if (ret != 0)
                        goto out;
        }

        data = dict_get (xattr_req, "system.cdp_acl_default");
        if (data) {
                ret = sys_lsetxattr (path, "system.cdp_acl_default",
                                     data->data, data->len, 0);
                if (ret != 0)
                        goto out;
        }

out:
        return ret;
}

int
cdp_entry_create_xattr_set (xlator_t *this, const char *path,
                             dict_t *dict)
{
        data_pair_t *trav = NULL;
        int ret = -1;

        trav = dict->members_list;
        while (trav) {
                if (!strcmp (GFID_XATTR_KEY, trav->key) ||
                    !strcmp ("gfid-req", trav->key) ||
                    !strcmp ("system.cdp_acl_default", trav->key) ||
                    !strcmp ("system.cdp_acl_access", trav->key) ||
                    ZR_FILE_CONTENT_REQUEST(trav->key)) {
                        trav = trav->next;
                        continue;
                }

                ret = cdp_handle_pair (this, path, trav, XATTR_CREATE);
                if (ret < 0) {
                        errno = -ret;
                        ret = -1;
                        goto out;
                }
                trav = trav->next;
        }

        ret = 0;

out:
        return ret;
}


int
create_gfid_directory_path (xlator_t *this, uuid_t gfid, mode_t type)
{
        int      ret  = -1;
        int32_t  dir1 = 0;
        int32_t  dir2 = 0;
        char    *path = NULL;

        if (uuid_is_null (gfid))
                goto out;

        path = alloca (1024);
        if (!path)
                goto out;

        dir1 = gfid[0] + ((int)(gfid[1] & 0x3f) << 8);
        dir2 = gfid[2] + ((int)(gfid[3] & 0x3f) << 8);

        snprintf (path, 1024, "%s/%d",
                  CDP_BASE_PATH(this),dir1);
        ret = mkdir (path, 0777);
        if ((ret == -1) && (errno != EEXIST))
                goto out;

        snprintf (path, 1024, "%s/%d/%d",
                  CDP_BASE_PATH(this),dir1,dir2);
        ret = mkdir (path, 0777);
        if ((ret == -1) && (errno != EEXIST))
                goto out;

        snprintf (path, 1024, "%s/%d/%d/%s",
                  CDP_BASE_PATH(this),dir1,dir2,
                  uuid_utoa (gfid));
        ret = mkdir (path, 0777);
        if (ret)
                goto out;

        snprintf (path, 1024, "%s/%d/%d/%s/HEAD/",
                  CDP_BASE_PATH(this),dir1,dir2,
                  uuid_utoa (gfid));
        ret = mkdir (path, (type & 0777));
        if (ret)
                goto out;

        ret = 0;
        snprintf (path, 1024, "%s/%d/%d/%s/type",
                  CDP_BASE_PATH(this),dir1,dir2,
                  uuid_utoa (gfid));
        switch (type & S_IFMT) {
        case S_IFDIR:
                ret = mkdir (path, type);
                break;
        case S_IFLNK:
                ret = symlink ("glusterfs-symlink-type", path);
                break;
        case S_IFBLK:
        case S_IFCHR:
                /* needs the 'dev' values to be set */
                ret = mknod (path, type, makedev (13, 42));
                break;
        default:
                ret = mknod (path, type, 0);
                break;
        }
out:
        if (ret)
                gf_log (this->name, GF_LOG_ERROR,
                        "failed to create the parent directory %s (%s)",
                        path, strerror (errno));

        return ret;
}

int
is_gfid_dir_empty (xlator_t *this, const char *path)
{
        struct dirent *entry     = NULL;
        char          *gfid_path = NULL;
        DIR           *dir       = NULL;
        uuid_t         gfid      = {0,};
        int            ret       = 1;
        int            op_ret    = 0;

        op_ret = sys_lgetxattr (path, GFID_XATTR_KEY, gfid, 16);
        /* Return value of getxattr */
        if (op_ret == 16)
                op_ret = 0;

        if (op_ret)
                goto out;

        MAKE_GFID_PATH (gfid_path, this, gfid);

        dir = opendir (gfid_path);
        if (!dir)
                goto out;

        while (1) {
                entry = readdir (dir);
                if (!entry)
                        goto out;

                if (strcmp (entry->d_name, ".") && strcmp (entry->d_name, "..")) {
                        gf_log (this->name, 1, "%s", entry->d_name);
                        ret = 0;
                        goto out;
                }
        }

out:
        if (dir)
                closedir (dir);
        return ret;
}
