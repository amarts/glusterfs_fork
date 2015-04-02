/*
 *  Copyright (c) 2013 Red Hat, Inc. <http://www.redhat.com>
 *  This file is part of GlusterFS.
 *
 *  This file is licensed to you under your choice of the GNU Lesser
 *  General Public License, version 3 or any later version (LGPLv3 or
 *  later), or the GNU General Public License, version 2 (GPLv2), in all
 *  cases as published by the Free Software Foundation.
 */


#include "glfs-internal.h"
#include "glfs-mem-types.h"
#include "syncop.h"
#include "glfs.h"
#include "glfs-handles.h"

int
glfs_listxattr_process (void *value, size_t size, dict_t *xattr);

static void
glfs_iatt_from_stat (struct stat *stat, int valid, struct iatt *iatt,
                     int *glvalid)
{
        /* validate in args */
        if ((stat == NULL) || (iatt == NULL) || (glvalid == NULL)) {
                errno = EINVAL;
                return;
        }

        *glvalid = 0;

        if (valid & GFAPI_SET_ATTR_MODE) {
                iatt->ia_prot = ia_prot_from_st_mode (stat->st_mode);
                *glvalid |= GF_SET_ATTR_MODE;
        }

        if (valid & GFAPI_SET_ATTR_UID) {
                iatt->ia_uid = stat->st_uid;
                *glvalid |= GF_SET_ATTR_UID;
        }

        if (valid & GFAPI_SET_ATTR_GID) {
                iatt->ia_gid = stat->st_gid;
                *glvalid |= GF_SET_ATTR_GID;
        }

        if (valid & GFAPI_SET_ATTR_ATIME) {
                iatt->ia_atime = stat->st_atime;
                iatt->ia_atime_nsec = ST_ATIM_NSEC (stat);
                *glvalid |= GF_SET_ATTR_ATIME;
        }

        if (valid & GFAPI_SET_ATTR_MTIME) {
                iatt->ia_mtime = stat->st_mtime;
                iatt->ia_mtime_nsec = ST_MTIM_NSEC (stat);
                *glvalid |= GF_SET_ATTR_MTIME;
        }

        return;
}

struct glfs_object *
pub_glfs_h_lookupat (struct glfs *fs, struct glfs_object *parent,
                     const char *path, struct stat *stat)
{
        int                      ret = 0;
        xlator_t                *subvol = NULL;
        inode_t                 *inode = NULL;
        struct iatt              iatt = {0, };
        struct glfs_object      *object = NULL;
        loc_t                    loc = {0, };

        /* validate in args */
        if ((fs == NULL) || (path == NULL)) {
                errno = EINVAL;
                return NULL;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        if (parent) {
                inode = glfs_resolve_inode (fs, subvol, parent);
                if (!inode) {
                        errno = ESTALE;
                        goto out;
                }
        }

        /* fop/op */
        ret = glfs_resolve_at (fs, subvol, inode, path, &loc, &iatt,
                                    0 /*TODO: links? */, 0);

        /* populate out args */
        if (!ret) {
                if (stat)
                        glfs_iatt_to_stat (fs, &iatt, stat);

                ret = glfs_create_object (&loc, &object);
        }

out:
        loc_wipe (&loc);

        if (inode)
                inode_unref (inode);

        glfs_subvol_done (fs, subvol);

        return object;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_lookupat, 3.4.2);


int
pub_glfs_h_stat (struct glfs *fs, struct glfs_object *object, struct stat *stat)
{
        int              ret = -1;
        xlator_t        *subvol = NULL;
        inode_t         *inode = NULL;
        loc_t            loc = {0, };
        struct iatt      iatt = {0, };

        /* validate in args */
        if ((fs == NULL) || (object == NULL)) {
                errno = EINVAL;
                return -1;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, object);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        /* populate loc */
        GLFS_LOC_FILL_INODE (inode, loc, out);

        /* fop/op */
        ret = syncop_stat (subvol, &loc, &iatt);
        DECODE_SYNCOP_ERR (ret);

        /* populate out args */
        if (!ret && stat) {
                glfs_iatt_to_stat (fs, &iatt, stat);
        }
out:
        loc_wipe (&loc);

        if (inode)
                inode_unref (inode);

        glfs_subvol_done (fs, subvol);

        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_stat, 3.4.2);


int
pub_glfs_h_getattrs (struct glfs *fs, struct glfs_object *object,
                     struct stat *stat)
{
        int                      ret = 0;
        xlator_t                *subvol = NULL;
        inode_t                 *inode = NULL;
        struct iatt              iatt = {0, };

        /* validate in args */
        if ((fs == NULL) || (object == NULL)) {
                errno = EINVAL;
                return -1;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, object);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        /* fop/op */
        ret = glfs_resolve_base (fs, subvol, inode, &iatt);

        /* populate out args */
        if (!ret && stat) {
                glfs_iatt_to_stat (fs, &iatt, stat);
        }

out:
        if (inode)
                inode_unref (inode);

        glfs_subvol_done (fs, subvol);

        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_getattrs, 3.4.2);


int
glfs_h_getxattrs_common (struct glfs *fs, struct glfs_object *object,
                         dict_t **xattr, const char *name)
{
        int                 ret = 0;
        xlator_t        *subvol = NULL;
        inode_t         *inode = NULL;
        loc_t            loc = {0, };

        /* validate in args */
        if ((fs == NULL) || (object == NULL)) {
                errno = EINVAL;
                return -1;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, object);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        /* populate loc */
        GLFS_LOC_FILL_INODE (inode, loc, out);

        ret = syncop_getxattr (subvol, &loc, xattr, name, NULL);
        DECODE_SYNCOP_ERR (ret);

out:
        loc_wipe (&loc);

        if (inode)
                inode_unref (inode);

        glfs_subvol_done (fs, subvol);

        return ret;
}


int
pub_glfs_h_getxattrs (struct glfs *fs, struct glfs_object *object,
                      const char *name, void *value, size_t size)
{
        int                 ret = 0;
        dict_t                *xattr = NULL;

        /* validate in args */
        if ((fs == NULL) || (object == NULL)) {
                errno = EINVAL;
                return -1;
        }

        ret = glfs_h_getxattrs_common (fs, object, &xattr, name);
        if (ret)
                goto out;

        /* If @name is NULL, means get all the xattrs (i.e listxattr). */
        if (name)
                ret = glfs_getxattr_process (value, size, xattr, name);
        else
                ret = glfs_listxattr_process (value, size, xattr);

out:
        if (xattr)
                dict_unref (xattr);
        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_getxattrs, 3.5.1);

int
pub_glfs_h_setattrs (struct glfs *fs, struct glfs_object *object,
                     struct stat *stat, int valid)
{
        int              ret = -1;
        xlator_t        *subvol = NULL;
        inode_t         *inode = NULL;
        loc_t            loc = {0, };
        struct iatt      iatt = {0, };
        int              glvalid = 0;

        /* validate in args */
        if ((fs == NULL) || (object == NULL) || (stat == NULL)) {
                errno = EINVAL;
                return -1;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, object);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        /* map valid masks from in args */
        glfs_iatt_from_stat (stat, valid, &iatt, &glvalid);

        /* populate loc */
        GLFS_LOC_FILL_INODE (inode, loc, out);

        /* fop/op */
        ret = syncop_setattr (subvol, &loc, &iatt, glvalid, 0, 0);
        DECODE_SYNCOP_ERR (ret);
out:
        loc_wipe (&loc);

        if (inode)
                inode_unref (inode);

        glfs_subvol_done (fs, subvol);

        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_setattrs, 3.4.2);


int
pub_glfs_h_setxattrs (struct glfs *fs, struct glfs_object *object,
                      const char *name, const void *value, size_t size,
                      int flags)
{
        int              ret = -1;
        xlator_t        *subvol = NULL;
        inode_t         *inode = NULL;
        loc_t            loc = {0, };
        dict_t          *xattr = NULL;

        /* validate in args */
        if ((fs == NULL) || (object == NULL) ||
                 (name == NULL) || (value == NULL)) {
                errno = EINVAL;
                return -1;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, object);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        xattr = dict_for_key_value (name, value, size);
        if (!xattr) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }

        /* populate loc */
        GLFS_LOC_FILL_INODE (inode, loc, out);

        /* fop/op */
        ret = syncop_setxattr (subvol, &loc, xattr, flags);
        DECODE_SYNCOP_ERR (ret);

out:
        loc_wipe (&loc);

        if (inode)
                inode_unref (inode);

        if (xattr)
                dict_unref (xattr);

        glfs_subvol_done (fs, subvol);

        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_setxattrs, 3.5.0);


int
pub_glfs_h_removexattrs (struct glfs *fs, struct glfs_object *object,
                         const char *name)
{
        int              ret = -1;
        xlator_t        *subvol = NULL;
        inode_t         *inode = NULL;
        loc_t            loc = {0, };

        /* validate in args */
        if ((fs == NULL) || (object == NULL) || (name == NULL)) {
                errno = EINVAL;
                return -1;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, object);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        /* populate loc */
        GLFS_LOC_FILL_INODE (inode, loc, out);

        /* fop/op */
        ret = syncop_removexattr (subvol, &loc, name, 0);
        DECODE_SYNCOP_ERR (ret);

out:
        loc_wipe (&loc);

        if (inode)
                inode_unref (inode);

        glfs_subvol_done (fs, subvol);

        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_removexattrs, 3.5.1);


struct glfs_fd *
pub_glfs_h_open (struct glfs *fs, struct glfs_object *object, int flags)
{
        int              ret = -1;
        struct glfs_fd  *glfd = NULL;
        xlator_t        *subvol = NULL;
        inode_t         *inode = NULL;
        loc_t            loc = {0, };

        /* validate in args */
        if ((fs == NULL) || (object == NULL)) {
                errno = EINVAL;
                return NULL;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, object);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        /* check types to open */
        if (IA_ISDIR (inode->ia_type)) {
                ret = -1;
                errno = EISDIR;
                goto out;
        }

        if (!IA_ISREG (inode->ia_type)) {
                ret = -1;
                errno = EINVAL;
                goto out;
        }

        glfd = glfs_fd_new (fs);
        if (!glfd) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }

        glfd->fd = fd_create (inode, getpid());
        if (!glfd->fd) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }
        glfd->fd->flags = flags;

        /* populate loc */
        GLFS_LOC_FILL_INODE (inode, loc, out);

        /* fop/op */
        ret = syncop_open (subvol, &loc, flags, glfd->fd);
        DECODE_SYNCOP_ERR (ret);

        glfd->fd->flags = flags;
        fd_bind (glfd->fd);
        glfs_fd_bind (glfd);

out:
        loc_wipe (&loc);

        if (inode)
                inode_unref (inode);

        if (ret && glfd) {
                glfs_fd_destroy (glfd);
                glfd = NULL;
        }

        glfs_subvol_done (fs, subvol);

        return glfd;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_open, 3.4.2);


struct glfs_object *
pub_glfs_h_creat (struct glfs *fs, struct glfs_object *parent, const char *path,
                  int flags, mode_t mode, struct stat *stat)
{
        int                 ret = -1;
        struct glfs_fd     *glfd = NULL;
        xlator_t           *subvol = NULL;
        inode_t            *inode = NULL;
        loc_t               loc = {0, };
        struct iatt         iatt = {0, };
        uuid_t              gfid;
        dict_t             *xattr_req = NULL;
        struct glfs_object *object = NULL;

        /* validate in args */
        if ((fs == NULL) || (parent == NULL) || (path == NULL)) {
                errno = EINVAL;
                return NULL;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, parent);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        xattr_req = dict_new ();
        if (!xattr_req) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }

        gf_uuid_generate (gfid);
        ret = dict_set_static_bin (xattr_req, "gfid-req", gfid, 16);
        if (ret) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }

        GLFS_LOC_FILL_PINODE (inode, loc, ret, errno, out, path);

        glfd = glfs_fd_new (fs);
        if (!glfd) {
                 ret = -1;
                 errno = ENOMEM;
                 goto out;
        }

        glfd->fd = fd_create (loc.inode, getpid());
        if (!glfd->fd) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }
        glfd->fd->flags = flags;

        /* fop/op */
        ret = syncop_create (subvol, &loc, flags, mode, glfd->fd,
                             xattr_req, &iatt);
        DECODE_SYNCOP_ERR (ret);

        /* populate out args */
        if (ret == 0) {
                /* TODO: If the inode existed in the cache (say file already
                   exists), then the glfs_loc_link will not update the
                   loc.inode, as a result we will have a 0000 GFID that we
                   would copy out to the object, this needs to be fixed.
                */
                ret = glfs_loc_link (&loc, &iatt);
                if (ret != 0) {
                        goto out;
                }

                if (stat)
                        glfs_iatt_to_stat (fs, &iatt, stat);

                ret = glfs_create_object (&loc, &object);
        }

        glfd->fd->flags = flags;
        fd_bind (glfd->fd);
        glfs_fd_bind (glfd);

out:
        if (ret && object != NULL) {
                glfs_h_close (object);
                object = NULL;
        }

        loc_wipe(&loc);

        if (inode)
                inode_unref (inode);

        if (xattr_req)
                dict_unref (xattr_req);

        if (glfd) {
                glfs_fd_destroy (glfd);
                glfd = NULL;
        }

        glfs_subvol_done (fs, subvol);

        return object;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_creat, 3.4.2);


struct glfs_object *
pub_glfs_h_mkdir (struct glfs *fs, struct glfs_object *parent, const char *path,
                  mode_t mode, struct stat *stat)
{
        int                 ret = -1;
        xlator_t           *subvol = NULL;
        inode_t            *inode = NULL;
        loc_t               loc = {0, };
        struct iatt         iatt = {0, };
        uuid_t              gfid;
        dict_t             *xattr_req = NULL;
        struct glfs_object *object = NULL;

        /* validate in args */
        if ((fs == NULL) || (parent == NULL) || (path == NULL)) {
                errno = EINVAL;
                return NULL;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, parent);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        xattr_req = dict_new ();
        if (!xattr_req) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }

        gf_uuid_generate (gfid);
        ret = dict_set_static_bin (xattr_req, "gfid-req", gfid, 16);
        if (ret) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }

        GLFS_LOC_FILL_PINODE (inode, loc, ret, errno, out, path);

        /* fop/op */
        ret = syncop_mkdir (subvol, &loc, mode, xattr_req, &iatt);
        DECODE_SYNCOP_ERR (ret);

        /* populate out args */
        if ( ret == 0 )  {
                ret = glfs_loc_link (&loc, &iatt);
                if (ret != 0) {
                        goto out;
                }

                if (stat)
                        glfs_iatt_to_stat (fs, &iatt, stat);

                ret = glfs_create_object (&loc, &object);
        }

out:
        if (ret && object != NULL) {
                glfs_h_close (object);
                object = NULL;
        }

        loc_wipe(&loc);

        if (inode)
                inode_unref (inode);

        if (xattr_req)
                dict_unref (xattr_req);

        glfs_subvol_done (fs, subvol);

        return object;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_mkdir, 3.4.2);


struct glfs_object *
pub_glfs_h_mknod (struct glfs *fs, struct glfs_object *parent, const char *path,
                  mode_t mode, dev_t dev, struct stat *stat)
{
        int                 ret = -1;
        xlator_t           *subvol = NULL;
        inode_t            *inode = NULL;
        loc_t               loc = {0, };
        struct iatt         iatt = {0, };
        uuid_t              gfid;
        dict_t             *xattr_req = NULL;
        struct glfs_object *object = NULL;

        /* validate in args */
        if ((fs == NULL) || (parent == NULL) || (path == NULL)) {
                errno = EINVAL;
                return NULL;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, parent);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        xattr_req = dict_new ();
        if (!xattr_req) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }

        gf_uuid_generate (gfid);
        ret = dict_set_static_bin (xattr_req, "gfid-req", gfid, 16);
        if (ret) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }

        GLFS_LOC_FILL_PINODE (inode, loc, ret, errno, out, path);

        /* fop/op */
        ret = syncop_mknod (subvol, &loc, mode, dev, xattr_req, &iatt);
        DECODE_SYNCOP_ERR (ret);

        /* populate out args */
        if (ret == 0) {
                ret = glfs_loc_link (&loc, &iatt);
                if (ret != 0) {
                        goto out;
                }

                if (stat)
                        glfs_iatt_to_stat (fs, &iatt, stat);

                ret = glfs_create_object (&loc, &object);
        }
out:
        if (ret && object != NULL) {
                glfs_h_close (object);
                object = NULL;
        }

        loc_wipe(&loc);

        if (inode)
                inode_unref (inode);

        if (xattr_req)
                dict_unref (xattr_req);

        glfs_subvol_done (fs, subvol);

        return object;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_mknod, 3.4.2);


int
pub_glfs_h_unlink (struct glfs *fs, struct glfs_object *parent, const char *path)
{
        int                 ret = -1;
        xlator_t           *subvol = NULL;
        inode_t            *inode = NULL;
        loc_t               loc = {0, };

        /* validate in args */
        if ((fs == NULL) || (parent == NULL) || (path == NULL)) {
                errno = EINVAL;
                return -1;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if ( !subvol ) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, parent);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        ret = glfs_resolve_at (fs, subvol, inode, path, &loc, NULL, 0 , 0);
        if (ret != 0) {
                goto out;
        }

        if (!IA_ISDIR(loc.inode->ia_type)) {
                ret = syncop_unlink (subvol, &loc);
                DECODE_SYNCOP_ERR (ret);
                if (ret != 0) {
                        goto out;
                }
        } else {
                ret = syncop_rmdir (subvol, &loc, 0);
                DECODE_SYNCOP_ERR (ret);
                if (ret != 0) {
                        goto out;
                }
        }

        if (ret == 0)
                ret = glfs_loc_unlink (&loc);

out:
        loc_wipe (&loc);

        if (inode)
                inode_unref (inode);

        glfs_subvol_done (fs, subvol);

        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_unlink, 3.4.2);


struct glfs_fd *
pub_glfs_h_opendir (struct glfs *fs, struct glfs_object *object)
{
        int              ret = -1;
        struct glfs_fd  *glfd = NULL;
        xlator_t        *subvol = NULL;
        inode_t         *inode = NULL;
        loc_t            loc = {0, };

        /* validate in args */
        if ((fs == NULL) || (object == NULL)) {
                errno = EINVAL;
                return NULL;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, object);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        if (!IA_ISDIR (inode->ia_type)) {
                ret = -1;
                errno = ENOTDIR;
                goto out;
        }

        glfd = glfs_fd_new (fs);
        if (!glfd)
                goto out;

        INIT_LIST_HEAD (&glfd->entries);

        glfd->fd = fd_create (inode, getpid());
        if (!glfd->fd) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }

        GLFS_LOC_FILL_INODE (inode, loc, out);

        /* fop/op */
        ret = syncop_opendir (subvol, &loc, glfd->fd);
        DECODE_SYNCOP_ERR (ret);

out:
        loc_wipe (&loc);

        if (inode)
                inode_unref (inode);

        if (ret && glfd) {
                glfs_fd_destroy (glfd);
                glfd = NULL;
        } else {
                fd_bind (glfd->fd);
                glfs_fd_bind (glfd);
        }

        glfs_subvol_done (fs, subvol);

        return glfd;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_opendir, 3.4.2);


int
pub_glfs_h_access (struct glfs *fs, struct glfs_object *object, int mask)
{
	int              ret = -1;
	xlator_t        *subvol = NULL;
	inode_t         *inode = NULL;
	loc_t            loc = {0, };

	/* validate in args */
	if ((fs == NULL) || (object == NULL)) {
		errno = EINVAL;
		goto out;
	}

	__glfs_entry_fs (fs);

	/* get the active volume */
	subvol = glfs_active_subvol (fs);
	if (!subvol) {
		ret = -1;
		errno = EIO;
		goto out;
	}

	/* get/refresh the in arg objects inode in correlation to the xlator */
	inode = glfs_resolve_inode (fs, subvol, object);
	if (!inode) {
		errno = ESTALE;
		goto out;
	}


	GLFS_LOC_FILL_INODE (inode, loc, out);

	/* fop/op */

	ret = syncop_access (subvol, &loc, mask);
        DECODE_SYNCOP_ERR (ret);

out:
	loc_wipe (&loc);

	if (inode)
		inode_unref (inode);


	glfs_subvol_done (fs, subvol);

	return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_access, 3.6.0);


ssize_t
pub_glfs_h_extract_handle (struct glfs_object *object, unsigned char *handle,
                           int len)
{
        ssize_t ret = -1;

        /* validate in args */
        if (object == NULL) {
                errno = EINVAL;
                goto out;
        }

        if (!handle || !len) {
                ret = GFAPI_HANDLE_LENGTH;
                goto out;
        }

        if (len < GFAPI_HANDLE_LENGTH)
        {
                errno = ERANGE;
                goto out;
        }

        memcpy (handle, object->gfid, GFAPI_HANDLE_LENGTH);

        ret = GFAPI_HANDLE_LENGTH;

out:
        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_extract_handle, 3.4.2);


struct glfs_object *
pub_glfs_h_create_from_handle (struct glfs *fs, unsigned char *handle, int len,
                               struct stat *stat)
{
        loc_t               loc = {0, };
        int                 ret = -1;
        struct iatt         iatt = {0, };
        inode_t            *newinode = NULL;
        xlator_t           *subvol = NULL;
        struct glfs_object *object = NULL;

        /* validate in args */
        if ((fs == NULL) || (handle == NULL) || (len != GFAPI_HANDLE_LENGTH)) {
                errno = EINVAL;
                return NULL;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                errno = EIO;
                goto out;
        }

        memcpy (loc.gfid, handle, GFAPI_HANDLE_LENGTH);

        newinode = inode_find (subvol->itable, loc.gfid);
        if (newinode)
                loc.inode = newinode;
        else {
                loc.inode = inode_new (subvol->itable);
                if (!loc.inode) {
                        errno = ENOMEM;
                        goto out;
                }
        }

        ret = syncop_lookup (subvol, &loc, 0, &iatt, 0, 0);
        DECODE_SYNCOP_ERR (ret);
        if (ret) {
                gf_log (subvol->name, GF_LOG_WARNING,
                        "inode refresh of %s failed: %s",
                        uuid_utoa (loc.gfid), strerror (errno));
                goto out;
        }

        newinode = inode_link (loc.inode, 0, 0, &iatt);
        if (newinode)
                inode_lookup (newinode);
        else {
                gf_log (subvol->name, GF_LOG_WARNING,
                        "inode linking of %s failed: %s",
                        uuid_utoa (loc.gfid), strerror (errno));
                errno = EINVAL;
                goto out;
        }

        /* populate stat */
        if (stat)
                glfs_iatt_to_stat (fs, &iatt, stat);

        object = GF_CALLOC (1, sizeof(struct glfs_object),
                            glfs_mt_glfs_object_t);
        if (object == NULL) {
                errno = ENOMEM;
                ret = -1;
                goto out;
        }

        /* populate the return object */
        object->inode = newinode;
        gf_uuid_copy (object->gfid, object->inode->gfid);

out:
        /* TODO: Check where the inode ref is being held? */
        loc_wipe (&loc);

        glfs_subvol_done (fs, subvol);

        return object;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_create_from_handle, 3.4.2);


int
pub_glfs_h_close (struct glfs_object *object)
{
        /* Release the held reference */
        inode_unref (object->inode);
        GF_FREE (object);

        return 0;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_close, 3.4.2);


int
pub_glfs_h_truncate (struct glfs *fs, struct glfs_object *object, off_t offset)
{
        loc_t               loc = {0, };
        int                 ret = -1;
        xlator_t           *subvol = NULL;
        inode_t            *inode = NULL;

        /* validate in args */
        if ((fs == NULL) || (object == NULL)) {
                errno = EINVAL;
                return -1;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, object);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        GLFS_LOC_FILL_INODE (inode, loc, out);

        /* fop/op */
        ret = syncop_truncate (subvol, &loc, (off_t)offset);
        DECODE_SYNCOP_ERR (ret);

        /* populate out args */
        if (ret == 0)
                ret = glfs_loc_unlink (&loc);

out:
        loc_wipe (&loc);

        if (inode)
                inode_unref (inode);

        glfs_subvol_done (fs, subvol);

        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_truncate, 3.4.2);


struct glfs_object *
pub_glfs_h_symlink (struct glfs *fs, struct glfs_object *parent,
                    const char *name, const char *data, struct stat *stat)
{
        int                 ret = -1;
        xlator_t           *subvol = NULL;
        inode_t            *inode = NULL;
        loc_t               loc = {0, };
        struct iatt         iatt = {0, };
        uuid_t              gfid;
        dict_t             *xattr_req = NULL;
        struct glfs_object *object = NULL;

        /* validate in args */
        if ((fs == NULL) || (parent == NULL) || (name == NULL) ||
                (data == NULL)) {
                errno = EINVAL;
                return NULL;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, parent);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        xattr_req = dict_new ();
        if (!xattr_req) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }

        gf_uuid_generate (gfid);
        ret = dict_set_static_bin (xattr_req, "gfid-req", gfid, 16);
        if (ret) {
                ret = -1;
                errno = ENOMEM;
                goto out;
        }

        GLFS_LOC_FILL_PINODE (inode, loc, ret, errno, out, name);

        /* fop/op */
        ret = syncop_symlink (subvol, &loc, data, xattr_req, &iatt);
        DECODE_SYNCOP_ERR (ret);

        /* populate out args */
        if (ret == 0) {
                /* TODO: If the inode existed in the cache (say file already
                 * exists), then the glfs_loc_link will not update the
                 * loc.inode, as a result we will have a 0000 GFID that we
                 * would copy out to the object, this needs to be fixed.
                 */
                ret = glfs_loc_link (&loc, &iatt);
                if (ret != 0) {
                        goto out;
                }

                if (stat)
                        glfs_iatt_to_stat (fs, &iatt, stat);

                ret = glfs_create_object (&loc, &object);
        }

out:
        if (ret && object != NULL) {
                pub_glfs_h_close (object);
                object = NULL;
        }

        loc_wipe(&loc);

        if (inode)
                inode_unref (inode);

        if (xattr_req)
                dict_unref (xattr_req);

        glfs_subvol_done (fs, subvol);

        return object;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_symlink, 3.4.2);


int
pub_glfs_h_readlink (struct glfs *fs, struct glfs_object *object, char *buf,
                     size_t bufsiz)
{
        loc_t               loc = {0, };
        int                 ret = -1;
        xlator_t           *subvol = NULL;
        inode_t            *inode = NULL;
        char               *linkval = NULL;

        /* validate in args */
        if ((fs == NULL) || (object == NULL) || (buf == NULL)) {
                errno = EINVAL;
                return -1;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, object);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        GLFS_LOC_FILL_INODE (inode, loc, out);

        /* fop/op */
        ret = syncop_readlink (subvol, &loc, &linkval, bufsiz);
        DECODE_SYNCOP_ERR (ret);

        /* populate out args */
        if (ret > 0)
                memcpy (buf, linkval, ret);

out:
        loc_wipe (&loc);

        if (inode)
                inode_unref (inode);

        if (linkval)
                GF_FREE (linkval);

        glfs_subvol_done (fs, subvol);

        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_readlink, 3.4.2);


int
pub_glfs_h_link (struct glfs *fs, struct glfs_object *linksrc,
             struct glfs_object *parent, const char *name)
{
        int                 ret = -1;
        xlator_t           *subvol = NULL;
        inode_t            *inode = NULL;
        inode_t            *pinode = NULL;
        loc_t               oldloc = {0, };
        loc_t               newloc = {0, };

        /* validate in args */
        if ((fs == NULL) || (linksrc == NULL) || (parent == NULL) ||
                (name == NULL)) {
                errno = EINVAL;
                return -1;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if (!subvol) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        inode = glfs_resolve_inode (fs, subvol, linksrc);
        if (!inode) {
                errno = ESTALE;
                goto out;
        }

        if (inode->ia_type == IA_IFDIR) {
                ret = -1;
                errno = EISDIR;
                goto out;
        }

        GLFS_LOC_FILL_INODE (inode, oldloc, out);

        /* get/refresh the in arg objects inode in correlation to the xlator */
        pinode = glfs_resolve_inode (fs, subvol, parent);
        if (!pinode) {
                errno = ESTALE;
                goto out;
        }

        /* setup newloc based on parent */
        newloc.parent = inode_ref (pinode);
        newloc.name = name;
        ret = glfs_loc_touchup (&newloc);
        if (ret != 0) {
                errno = EINVAL;
                goto out;
        }

        /* Filling the inode of the hard link to be same as that of the
         * original file
         */
        newloc.inode = inode_ref (inode);

        /* fop/op */
        ret = syncop_link (subvol, &oldloc, &newloc);
        DECODE_SYNCOP_ERR (ret);

        if (ret == 0)
                /* TODO: No iatt to pass as there has been no lookup */
                ret = glfs_loc_link (&newloc, NULL);
out:
        loc_wipe (&oldloc);
        loc_wipe (&newloc);

        if (inode)
                inode_unref (inode);

        if (pinode)
                inode_unref (pinode);

        glfs_subvol_done (fs, subvol);

        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_link, 3.4.2);


int
pub_glfs_h_rename (struct glfs *fs, struct glfs_object *olddir,
                   const char *oldname, struct glfs_object *newdir,
                   const char *newname)
{
        int                 ret = -1;
        xlator_t           *subvol = NULL;
        inode_t            *oldpinode = NULL;
        inode_t            *newpinode = NULL;
        loc_t               oldloc = {0, };
        loc_t               newloc = {0, };
        struct iatt         oldiatt = {0, };
        struct iatt         newiatt = {0, };

        /* validate in args */
        if ((fs == NULL) || (olddir == NULL) || (oldname == NULL) ||
                (newdir == NULL) || (newname == NULL)) {
                errno = EINVAL;
                return -1;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);
        if ( !subvol ) {
                ret = -1;
                errno = EIO;
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        oldpinode = glfs_resolve_inode (fs, subvol, olddir);
        if (!oldpinode) {
                errno = ESTALE;
                goto out;
        }

        ret = glfs_resolve_at (fs, subvol, oldpinode, oldname, &oldloc,
                                    &oldiatt, 0 , 0);
        if (ret != 0) {
                goto out;
        }

        /* get/refresh the in arg objects inode in correlation to the xlator */
        newpinode = glfs_resolve_inode (fs, subvol, newdir);
        if (!newpinode) {
                errno = ESTALE;
                goto out;
        }

        ret = glfs_resolve_at (fs, subvol, newpinode, newname, &newloc,
                                    &newiatt, 0, 0);

        if (ret && errno != ENOENT && newloc.parent)
                goto out;

        if (newiatt.ia_type != IA_INVAL) {
                if ((oldiatt.ia_type == IA_IFDIR) !=
                        (newiatt.ia_type == IA_IFDIR)) {
                        /* Either both old and new must be dirs,
                         * or both must be non-dirs. Else, fail.
                         */
                        ret = -1;
                        errno = EEXIST;
                        goto out;
                }
        }

        /* TODO: check if new or old is a prefix of the other, and fail EINVAL */

        ret = syncop_rename (subvol, &oldloc, &newloc);
        DECODE_SYNCOP_ERR (ret);

        if (ret == 0)
                inode_rename (oldloc.parent->table, oldloc.parent, oldloc.name,
                              newloc.parent, newloc.name, oldloc.inode,
                              &oldiatt);

out:
        loc_wipe (&oldloc);
        loc_wipe (&newloc);

        if (oldpinode)
                inode_unref (oldpinode);

        if (newpinode)
                inode_unref (newpinode);

        glfs_subvol_done (fs, subvol);

        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_rename, 3.4.2);

/*
 * This API is used to poll for upcall events stored in the
 * upcall list. Current users of this API is NFS-Ganesha.
 * Incase of any event received, it will be mapped appropriately
 * into 'callback_arg' along with the handle object  to be passed
 * to NFS-Ganesha.
 *
 * On success, applications need to check for 'object' to decide
 * if any upcall event is received.
 *
 * After processing the event, they need to free "object"
 * using glfs_h_close(..).
 *
 * Also similar to I/Os, the application should ideally stop polling
 * before calling glfs_fini(..). Hence making an assumption that
 * 'fs' & ctx structures cannot be freed while in this routine.
 */
int
pub_glfs_h_poll_upcall (struct glfs *fs, struct callback_arg *up_arg)
{
        struct glfs_object  *object   = NULL;
        uuid_t              gfid;
        upcall_entry        *u_list   = NULL;
        upcall_entry        *tmp      = NULL;
        xlator_t            *subvol   = NULL;
        int                 found     = 0;
        int                 reason    = 0;
        glusterfs_ctx_t     *ctx      = NULL;
        int                 ret       = -1;

        if (!fs || !up_arg) {
                errno = EINVAL;
                goto err;
        }

        __glfs_entry_fs (fs);

        /* get the active volume */
        subvol = glfs_active_subvol (fs);

        if (!subvol) {
                errno = EIO;
                goto err;
        }

        up_arg->object = NULL;

        /* Ideally applications should stop polling before calling
         * 'glfs_fini'. Yet cross check if cleanup has started
         */
        pthread_mutex_lock (&fs->mutex);
        {
                ctx = fs->ctx;

                if (ctx->cleanup_started) {
                        pthread_mutex_unlock (&fs->mutex);
                        goto out;
                }

                fs->pin_refcnt++;
        }
        pthread_mutex_unlock (&fs->mutex);

        pthread_mutex_lock (&fs->upcall_list_mutex);
        {
                list_for_each_entry_safe (u_list, tmp,
                                          &fs->upcall_list,
                                          upcall_list) {
                        gf_uuid_copy (gfid, u_list->gfid);
                        found = 1;
                        break;
                }
        }
        /* No other thread can delete this entry. So unlock it */
        pthread_mutex_unlock (&fs->upcall_list_mutex);

        if (found) {
                object = glfs_h_create_from_handle (fs, gfid,
                                                    GFAPI_HANDLE_LENGTH,
                                                    &up_arg->buf);

                if (!object) {
                        errno = ENOMEM;
                        goto out;
                }

                switch (u_list->event_type) {
                case CACHE_INVALIDATION:
                        if (u_list->flags & (~(INODE_UPDATE_FLAGS))) {
                                /* Invalidate CACHE */
                                reason = INODE_INVALIDATE;
                                gf_log (subvol->name, GF_LOG_DEBUG,
                                        "Reason - INODE_INVALIDATION");
                        } else {
                                reason = INODE_UPDATE;
                                gf_log (subvol->name, GF_LOG_DEBUG,
                                        "Reason - INODE_UPDATE");
                        }
                        break;
                default:
                        break;
                }

                up_arg->object = object;
                up_arg->reason = reason;
                up_arg->flags = u_list->flags;
                up_arg->expire_time_attr = u_list->expire_time_attr;

                list_del_init (&u_list->upcall_list);
                GF_FREE (u_list);
        }

        ret = 0;

out:
        pthread_mutex_lock (&fs->mutex);
        {
                fs->pin_refcnt--;
        }
        pthread_mutex_unlock (&fs->mutex);

        glfs_subvol_done (fs, subvol);

err:
        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_poll_upcall, 3.7.0);

#ifdef HAVE_ACL_LIBACL_H
#include "glusterfs-acl.h"
#include <acl/libacl.h>

int
pub_glfs_h_acl_set (struct glfs *fs, struct glfs_object *object,
                    const acl_type_t type, const acl_t acl)
{
        int ret = -1;
        char *acl_s = NULL;
        const char *acl_key = NULL;
        ssize_t acl_len = 0;

        if (!fs || !object || !acl) {
                errno = EINVAL;
                return ret;
        }

        acl_key = gf_posix_acl_get_key (type);
        if (!acl_key)
                return ret;

        acl_s = acl_to_any_text (acl, NULL, ',',
                                 TEXT_ABBREVIATE | TEXT_NUMERIC_IDS);
        if (!acl_s)
                return ret;

        ret = pub_glfs_h_setxattrs (fs, object, acl_key, acl_s, acl_len, 0);

        acl_free (acl_s);
        return ret;
}

acl_t
pub_glfs_h_acl_get (struct glfs *fs, struct glfs_object *object,
                    const acl_type_t type)
{
        int                 ret = 0;
        acl_t acl = NULL;
        char *acl_s = NULL;
        dict_t *xattr = NULL;
        const char *acl_key = NULL;

        if (!fs || !object) {
                errno = EINVAL;
                return NULL;
        }

        acl_key = gf_posix_acl_get_key (type);
        if (!acl_key)
                return NULL;

        ret = glfs_h_getxattrs_common (fs, object, &xattr, acl_key);
        if (ret)
                return NULL;

        ret = dict_get_str (xattr, (char *)acl_key, &acl_s);
        if (ret == -1)
                goto out;

        acl = acl_from_text (acl_s);

out:
        GF_FREE (acl_s);
        return acl;
}
#else /* !HAVE_ACL_LIBACL_H */
acl_t
pub_glfs_h_acl_get (struct glfs *fs, struct glfs_object *object,
                    const acl_type_t type)
{
        errno = ENOTSUP;
        return NULL;
}

int
pub_glfs_h_acl_set (struct glfs *fs, struct glfs_object *object,
                    const acl_type_t type, const acl_t acl)
{
        errno = ENOTSUP;
        return -1;
}
#endif
GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_acl_set, 3.7.0);
GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_h_acl_get, 3.7.0);
