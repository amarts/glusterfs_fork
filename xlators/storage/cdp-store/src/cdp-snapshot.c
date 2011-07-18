/*
  Copyright (c) 2011 Gluster, Inc. <http://www.gluster.com>
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

#include "cdp.h"
#include "cdp-mem-types.h"
#include "syscall.h"
#include "byte-order.h"


static int
sort_info_array (struct snap_info *curr, struct snap_info **new, int32_t len)
{
        int      idx      = 0;
        int      i        = 0;
        uint64_t tmp      = 0;

        struct snap_info *trav = NULL;

        trav = GF_CALLOC (sizeof (struct snap_info), len, 0);

        memcpy (trav, curr, (sizeof (struct snap_info) * len));

        /* Sort first */
        for (idx = 0; idx < len; idx++) {
                for (i = idx+1; i < len; i++) {
                        if (trav[idx].start > trav[i].start) {
                                tmp = trav[idx].start;
                                trav[idx].start = trav[i].start;
                                trav[i].start = tmp;
                                tmp = trav[idx].size;
                                trav[idx].size  = trav[i].size;
                                trav[i].size = tmp;
                        }
                }
        }

        /* Merge now */
        idx = 0;
        for (i = 1; i < (len-1); i++) {
                /* Increment the count */
                /*
                |------|
                          |-----|
                */
                if ((trav[idx].start + trav[idx].size) < trav[i].start) {
                        idx++;
                        trav[idx].start = trav[i].start;
                        trav[idx].size = trav[i].size;
                        continue;
                }

                /* Increase the 'size' */
                /*
                |------|
                       |------|


                |------|
                     |------|


                |------|
                |-----------|

                */
                if ((trav[idx].start + trav[idx].size) < (trav[i].start +
                                                          trav[i].size)) {
                        tmp = trav[i].size + trav[i].start;
                        trav[idx].size = tmp - trav[idx].start;
                        continue;
                }

                /* neglect the entry */
                /*
                |------|
                   |--|


                |------|
                |----|

                */
        }

        /* the latest 'idx' still points to valid entry, so increment it */
        idx++;

        *new = trav;

        if (len > idx) {
                gf_log ("sorting", GF_LOG_DEBUG, "reduced number of entries "
                        "to %d from %d", idx, len);
        }

        return idx;
}

int
gf_sync_snap_info_file (struct snap_fds *snap)
{
        struct snap_info *new_info = NULL;
        int               ret      = 0;
        int               len      = 0;
        int               new_len  = 0;
        uint64_t          start    = 0;
        uint64_t          size     = 0;

        if (!snap)
                return 0;

        len = (snap->idx_len * sizeof (struct snap_info));

        if (!len)
                goto write_index_file;

        new_len = sort_info_array (snap->snap_idx, &new_info,
                                   snap->idx_len);

        if (new_len < snap->idx_len) {
                /* Update the current 'snap_idx' array */
                snap->idx_len = new_len;
                memcpy (snap->snap_idx, &new_info, (new_len *
                                                    sizeof (struct snap_info)));
        }
        for (ret = 0; ret < new_len; ret++) {
                start = hton64 (new_info[ret].start);
                size  = hton64 (new_info[ret].size);
                new_info[ret].size  = size;
                new_info[ret].start = start;
        }

        len = (new_len * sizeof (struct snap_info));

write_index_file:
        lseek (snap->idx_fd, 0, SEEK_SET);
        if (len)
                ret = write (snap->idx_fd, (void *)new_info, len);
        else
                ret = ftruncate (snap->idx_fd, 0);

        if (new_info)
                GF_FREE (new_info);
        return ret;
}

int
gf_sync_and_free_pfd (xlator_t *this, struct cdp_fd *pfd)
{
        int i = 0;

        gf_sync_snap_info_file (&pfd->snap_fd[0]);

        for (i = 1; i < pfd->fd_count; i++) {
                close (pfd->snap_fd[i].fd);
                GF_FREE (pfd->snap_fd[i].snap_idx);
                pfd->snap_fd[i].snap_idx = NULL;
        }
        close (pfd->snap_fd[0].idx_fd);
        GF_FREE (pfd->snap_fd[0].snap_idx);
        pfd->snap_fd[0].snap_idx = NULL;

        pfd->snap_fd[0].idx_len = 0;

        return 0;
}

static int
gf_create_snap_index (const char *path, const char *snap_name, off_t start,
                      size_t size)
{
        int ret = -1;
        int fd = 0;
        struct snap_info snap = {0,};
        char index_path[ZR_PATH_MAX] = {0,};

        snprintf (index_path, ZR_PATH_MAX, "%s/%s/index", path, snap_name);

        fd = creat (index_path, 0400);
        if (fd < 0)
                goto out;

        if (size || start) {
                snap.start = hton64 (start);
                snap.size  = hton64 (size);

                ret = write (fd, &snap, sizeof (struct snap_info));
                if (ret < 0)
                        goto out;
        }

        ret = close (fd);
out:
        return ret;
}

/* 0 for not a snapshot file, 1 for yes */
int
gf_is_a_snapshot_file (xlator_t *this, uuid_t gfid)
{
        int ret = 0;
        char *snappath = NULL;
        struct stat statbuf = {0,};

        MAKE_ONLY_GFID_PATH (snappath, this, gfid);

        strcat (snappath, "/snapshot");

        ret = stat (snappath, &statbuf);
        if (!ret)
                return 1;

        return 0;
}

int
gf_create_directory_snapshot (xlator_t *this, inode_t *inode,
                              const char *snap_name)
{
        int            ret                    = -1;
        struct stat    stbuf                  = {0,};
        char          *gfidpath               = NULL;
        char           temp_path[ZR_PATH_MAX] = {0,};
        char           snap_path[ZR_PATH_MAX] = {0,};
        DIR           *dir                    = NULL;
        char           entry_path[PATH_MAX];
        char           target_path[PATH_MAX];
        struct stat    entrybuf               = {0,};
        uuid_t         entry_gfid             = {0,};
        struct dirent *entry                  = NULL;

        if (!inode || !snap_name)
                goto out;

        gf_log (this->name, GF_LOG_INFO, "path: (%s) snapshot: (%s)",
                gfidpath, snap_name);

        MAKE_ONLY_GFID_PATH (gfidpath, this, inode->gfid);

        /* NOTICE: inode wide lock */
        LOCK (&inode->lock);

        strcpy (temp_path, gfidpath);
        strcat (temp_path, "/snapshot");

        ret = mknod (temp_path, S_IFREG, 0);
        if (ret)
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to touch the snapshot entry %s",
                        strerror (errno));

        /* Rename the 'HEAD' to snap_name dir */
        {
                strcpy (snap_path, gfidpath);
                strcat (snap_path, "/");
                strcat (snap_path, snap_name);

                strcpy (temp_path, gfidpath);
                strcat (temp_path, "/HEAD");

                ret = stat (temp_path, &stbuf);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "stat failed on %s (%s)",
                                snap_path, strerror (errno));
                        goto unlock;
                }

                ret = sys_rename (temp_path, snap_path);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "rename %s -> %s (%s)",
                                temp_path, snap_path, strerror (errno));
                        goto unlock;
                }
        }

        /* Create the new 'HEAD' */
        {
                ret = mkdir (temp_path, stbuf.st_mode);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "mkdir failed on %s (%s)",
                                temp_path, strerror (errno));
                        goto unlock;
                }
                ret = chown (temp_path, stbuf.st_uid, stbuf.st_gid);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "chown failed on %s (%s)",
                                temp_path, strerror (errno));
                        goto unlock;
                }
        }

        /* Create the entries which were present on parent directory */
        {
                dir = opendir (snap_path);
                if (!dir)
                        goto unlock;

                while (1) {
                        entry = readdir (dir);
                        if (!entry)
                                goto unlock;

                        if (!strcmp (entry->d_name, ".") ||
                            !strcmp (entry->d_name, ".."))
                                continue;
                        snprintf (entry_path, PATH_MAX, "%s/%s",
                                  snap_path, entry->d_name);

                        ret = stat (entry_path, &entrybuf);
                        if (ret)
                                goto unlock;

                        snprintf (target_path, PATH_MAX, "%s/%s",
                                  temp_path, entry->d_name);
                        switch (entrybuf.st_mode & S_IFMT) {
                        case S_IFDIR:
                                ret = mkdir (target_path, entrybuf.st_mode);
                                break;
                        case S_IFLNK:
                                ret = symlink ("glusterfs-symlink-type",
                                               target_path);
                                break;
                        case S_IFBLK:
                        case S_IFCHR:
                                /* needs the 'dev' values to be set */
                                ret = mknod (target_path, entrybuf.st_mode,
                                             entrybuf.st_dev);
                                break;
                        default:
                                ret = mknod (target_path, entrybuf.st_mode, 0);
                                break;
                        }
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to create entry %s (%s)",
                                        target_path, strerror (errno));

                        ret = sys_lgetxattr (entry_path, GFID_XATTR_KEY,
                                             entry_gfid, 16);
                        if (ret == 16)
                                ret = sys_lsetxattr (target_path, GFID_XATTR_KEY,
                                                     entry_gfid, 16, 0);

                        if (ret)
                                gf_log (this->name, GF_LOG_WARNING,
                                        "failed to set gfid for entry %s (%s)",
                                        target_path, strerror (errno));
                }
        }
unlock:
        UNLOCK (&inode->lock);

        if (dir)
                closedir (dir);
out:
        return ret;
}

int
gf_create_snapshot (xlator_t *this, inode_t *inode, const char *snap_name)
{
        int              ret                      = -1;
        struct stat      stbuf                    = {0,};
        char            *gfidpath                 = NULL;
        char             temp_path[ZR_PATH_MAX]   = {0,};
        char             snap_path[ZR_PATH_MAX]   = {0,};
        char             parent_path[ZR_PATH_MAX] = {0,};
        fd_t            *iter_fd                  = NULL;
        struct cdp_fd   *pfd                      = NULL;
	uint64_t         tmp_pfd                  = 0;
        int              fd_found                 = 0;
        uuid_t           gfid                     = {0,};

        if (!inode || !snap_name)
                goto out;

        MAKE_ONLY_GFID_PATH (gfidpath, this, inode->gfid);

        gf_log (this->name, GF_LOG_INFO, "path: (%s) snapshot: (%s)",
                gfidpath, snap_name);

        /* NOTICE: inode wide lock */
        LOCK (&inode->lock);

        if (!list_empty (&inode->fd_list)) {
                list_for_each_entry (iter_fd, &inode->fd_list,
                                     inode_list) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "fd is open");
                        ret = fd_ctx_get (iter_fd, this, &tmp_pfd);
                        if (ret < 0) {
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "pfd not found in fd's ctx");
                                goto fd_check_done;
                        }
                        pfd = (struct cdp_fd *)(long)tmp_pfd;
                        gf_sync_and_free_pfd (this, pfd);
                        close (pfd->fd);
                        pfd->fd = 0;
                        fd_found = 1;
                }
        }

fd_check_done:
        strcpy (temp_path, gfidpath);
        strcat (temp_path, "/snapshot");

        ret = mknod (temp_path, S_IFREG, 0);
        if (ret)
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to touch the snapshot entry %s",
                        strerror (errno));

        {
                strcpy (snap_path, "../");
                strcat (snap_path, snap_name);

                strcpy (temp_path, gfidpath);
                strcat (temp_path, "/HEAD/parent/child");

                ret = symlink (snap_path, temp_path);
                if (ret && (errno != ENOENT)) {
                        gf_log (this->name, GF_LOG_ERROR, "symlink %s -> %s (%s)",
                                snap_path, temp_path, strerror (errno));
                        goto unlock;
                }
        }

        /* rename the delta present in 'HEAD/' to '$snap_name/' */
        {
                strcpy (snap_path, gfidpath);
                strcat (snap_path, "/");
                strcat (snap_path, snap_name);

                strcpy (temp_path, gfidpath);
                strcat (temp_path, "/HEAD");

                ret = sys_rename (temp_path, snap_path);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "rename %s -> %s",
                                temp_path, snap_path);
                        goto unlock;
                }
                strcat (snap_path, "/data");
                ret = stat (snap_path, &stbuf);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "stat %s", snap_path);
                        goto unlock;
                }

                /* TODO: decide on the permissions */
                ret = chmod (snap_path, 0400);
                if (ret) {
                        gf_log ("", 1, "");
                        goto unlock;
                }

                ret = gf_create_snap_index (gfidpath, snap_name, 0, stbuf.st_size);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to create index file %s (%s)",
                                gfidpath, strerror (errno));
                }

        }

        /* Create 'HEAD/' again to keep delta */
        {
                ret = mkdir (temp_path, 0750);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "mkdir %s", temp_path);
                        goto unlock;
                }
                ret = chown (temp_path, stbuf.st_uid, stbuf.st_gid);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "chown failed, %s", temp_path);
                        goto unlock;
                }

                strcat (temp_path, "/data");
                ret = mknod (temp_path, stbuf.st_mode, 0);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "mknod %s", temp_path);
                        goto unlock;
                }
                ret = chown (temp_path, stbuf.st_uid, stbuf.st_gid);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "chown failed, %s", temp_path);
                        goto unlock;
                }

                ret = sys_lsetxattr (temp_path, GFID_XATTR_KEY, gfid, 16, 0);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to set gfid %d on %s", ret, temp_path);
                        goto unlock;
                }

                ret = truncate (temp_path, stbuf.st_size);
                if (ret) {
                        gf_log ("", 1, "");
                        goto unlock;
                }

                ret = gf_create_snap_index (gfidpath, "HEAD", 0, 0);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to create index file %s (%s)",
                                gfidpath, strerror (errno));
                }
        }

        /* Create the link to parent snapshot */
        {
                strcpy (snap_path, gfidpath);
                strcat (snap_path, "/HEAD/parent");

                strcpy (parent_path, "../");
                strcat (parent_path, snap_name);

                ret = symlink (parent_path, snap_path);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "symlink %s -> %s",
                                parent_path, snap_path);
                        goto unlock;
                }
        }

        /* Open the fd if fd is found */
        if (fd_found) {
                list_for_each_entry (iter_fd, &inode->fd_list,
                                     inode_list) {
                        ret = fd_ctx_get (iter_fd, this, &tmp_pfd);
                        if (ret < 0) {
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "pfd not found in fd's ctx");
                                goto unlock;
                        }
                        pfd = (struct cdp_fd *)(long)tmp_pfd;
                        pfd->fd = gf_snapshot_open (this, pfd, inode,
                                                    NULL, pfd->flags);
                        if (pfd->fd == -1) {
                                ret = -1;
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to open the snapshot %s", gfidpath);
                                goto unlock;
                        }
                }
        }
unlock:
        UNLOCK (&inode->lock);

out:
        if (ret) {
                /* Revert back to normal file */
                /* TODO: change the log :p */
                gf_log (this->name, GF_LOG_ERROR, "something failed");
        } else {
                gf_log (this->name, GF_LOG_INFO, "snapshot successful");
        }

        return ret;
}

int
gf_snap_read_index_file (const char *index_path, int32_t open_flag,
                         struct snap_fds *snap)
{
        struct snap_info *trav     = NULL;
        struct stat       stbuf    = {0,};
        int               ret      = -1;
        size_t            len      = 0;
        size_t            i        = 0;
        int               index_fd = 0;
        uint64_t          start    = 0;
        uint64_t          size     = 0;
        int               calloc_len = 0;

        ret = stat (index_path, &stbuf);
        if (ret)
                goto out;

        len = stbuf.st_size / sizeof (struct snap_info);

        /* Open */
        calloc_len = len;
        if (open_flag != O_RDONLY) {
                calloc_len = len + 10000; /* TODO : */
        }

        if (calloc_len == 0) {
                ret = 0;
                snap->idx_len = 0;
                snap->snap_idx = NULL;
                goto out;
        }

        index_fd = open (index_path, open_flag);
        if (index_fd < 0) {
                ret = -1;
                goto out;
        }

        trav = GF_CALLOC (sizeof (struct snap_info), calloc_len,
                          gf_cdp_mt_snap_idx_t);

        /* read */
        ret = read (index_fd, trav, stbuf.st_size);
        if (ret < 0)
                goto out;

        for (i = 0; i < len; i++) {
                start = ntoh64 (trav[i].start);
                size  = ntoh64 (trav[i].size);

                trav[i].size = size;
                trav[i].start = start;
        }

        snap->snap_idx = trav;
        snap->idx_fd   = index_fd;
        snap->idx_len  = len;

        if (open_flag == O_RDONLY) {
                snap->idx_fd = 0;
                close (index_fd);
        }

        ret = 0;
out:
        return ret;
}


int
gf_snapshot_open (xlator_t *this, struct cdp_fd *pfd, inode_t *inode,
                  const char *snap_name, int32_t flags)
{
        struct stat stbuf                 = {0,};
        int         _fd                   = -1;
        int         ret                   = -1;
        int         data_fd               = -1;
        int         snap_count            = -1;
        int         idx                   = 0;
        char *gfidpath                    = NULL;
        char data_file_path[ZR_PATH_MAX]  = {0,};
        char index_file_path[ZR_PATH_MAX] = {0,};
        char parent_path[ZR_PATH_MAX]     = {0,};

        if (snap_name && ((O_ACCMODE & flags) != O_RDONLY)) {
                gf_log (this->name, GF_LOG_ERROR,
                        "only read only access on snapshots");
                errno = EPERM;
                ret = -1;
                goto out;
        }

        if (!snap_name)
                snap_name = "HEAD";

        MAKE_ONLY_GFID_PATH (gfidpath, this, inode->gfid);

        strcpy (data_file_path, gfidpath);
        strcat (data_file_path, "/");
        strcat (data_file_path, snap_name);
        strcat (data_file_path, "/data");

        strcpy (index_file_path, gfidpath);
        strcat (index_file_path, "/");
        strcat (index_file_path, snap_name);
        strcat (index_file_path, "/index");

        data_fd = open (data_file_path, flags);
        if (data_fd == -1) {
                gf_log_callingfn (this->name, GF_LOG_ERROR,
                                  "failed to open %s", data_file_path);
                goto out;
        }

        /* TODO: calculate the number of snapshots */
        snap_count = 13;

        pfd->snap_fd = GF_CALLOC (snap_count, sizeof (struct snap_fds), 0);

        _fd = data_fd;
        pfd->snap_fd[0].fd = data_fd;
        ret = gf_snap_read_index_file (index_file_path, O_RDWR, &pfd->snap_fd[0]);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR,
                        "failed to open %s", index_file_path);
                goto out;
        }
        strcpy (parent_path, gfidpath);
        strcat (parent_path, "/");
        strcat (parent_path, snap_name);
        strcat (parent_path, "/parent");

        idx = 1;
        ret = stat (parent_path, &stbuf);
        if (ret)
                goto done;

        while (1) {
                strcpy (data_file_path, parent_path);
                strcat (data_file_path, "/data");

                strcpy (index_file_path, parent_path);
                strcat (index_file_path, "/index");

                pfd->snap_fd[idx].fd = open (data_file_path, O_RDONLY);
                if (pfd->snap_fd[idx].fd == -1) {
                        ret = -1;
                        gf_log (this->name, GF_LOG_ERROR, "failed to open %s",
                                data_file_path);
                        goto out;
                }

                ret = gf_snap_read_index_file (index_file_path, O_RDONLY,
                                               &pfd->snap_fd[idx]);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "failed to open %s",
                                index_file_path);
                        goto out;
                }

                idx++;

                /*TODO: fix how we did our 'parent' link */
                strcat (parent_path, "/parent");

                ret = stat (parent_path, &stbuf);
                if (ret)
                        break;

        }
done:
        pfd->fd_count = idx;
        pfd->snapshot = 1;
        ret = 0;
out:
        if (ret) {
                /* Free up everything properly */
        }
        if (!ret) {
                /* Send the proper 'fd' back */
                ret = _fd;
        }

        return ret;
}

static size_t
get_next_recent_block (struct snap_fds *snapfd, off_t trav_off,
                       size_t trav_size, int fdidx, int arrayidx)
{
        int    k = 0;
        int    m = 0;
        size_t size1 = trav_size;

        for (k = 0; k < fdidx; k++) {
                for (m = 0; m < snapfd[k].idx_len; m++) {
                        if (m == arrayidx)
                                continue;
                        if ((snapfd[k].snap_idx[m].start > trav_off) &&
                            (snapfd[k].snap_idx[m].start < (trav_off + trav_size))) {
                                if (size1 > (snapfd[k].snap_idx[m].start -
                                             trav_off)) {
                                        size1 = (snapfd[k].snap_idx[m].start -
                                                 trav_off);
                                }
                        }
                }
        }
        return size1;
}

static int32_t
get_read_block_size (struct snap_fds *snapfd, int32_t fd_count, off_t trav_off,
                     size_t trav_size, size_t *return_size, int *_fd)
{
        size_t                 tmp_size   = 0;
        size_t                 tmp_size1  = 0;
        int32_t                i = 0;
        int32_t                j = 0;

        /* search for the proper block of the data */

        for (i = 0; i < fd_count; i++) {
                /* If the region is not in this 'fd', failover to next fd */
                for (j = 0; j < snapfd[i].idx_len; j++) {
                        if (!((snapfd[i].snap_idx[j].start <= trav_off) &&
                              ((snapfd[i].snap_idx[j].start +
                                snapfd[i].snap_idx[j].size) > trav_off))) {
                                continue;
                        }

                        tmp_size = (snapfd[i].snap_idx[j].size -
                                    (trav_off - snapfd[i].snap_idx[j].start));

                        /* get the next recent block */
                        tmp_size1 = get_next_recent_block (snapfd, trav_off,
                                                           trav_size, i, j);

                        if ((tmp_size1 != 0) && (tmp_size > tmp_size1)) {
                                tmp_size = tmp_size1;
                                tmp_size1 = 0;
                        }

                        if (tmp_size > trav_size)
                                tmp_size = trav_size;

                        *return_size = tmp_size;
                        *_fd = snapfd[i].fd;

                        return 0;
                }
        }

        return -1;
}

/* FIXME: I gotta tell you... this is one hell of a complex code :O */

int
gf_snap_readv (call_frame_t *frame, xlator_t *this, struct cdp_fd *pfd,
               off_t offset, size_t size)
{
        int32_t                op_ret     = -1;
        int32_t                op_errno   = 0;
        int                    _fd        = -1;
        int                    count      = 0;
        int                    eob_flag   = 1; /* end of block */
        off_t                  trav_off   = 0;
        off_t                  tmp_offset = 0;
        size_t                 tmp_size   = 0;
        size_t                 trav_size  = 0;
        size_t                 total_read = 0;
        struct cdp_private * priv       = NULL;
        struct iobuf         * iobuf      = NULL;
        struct iobref        * iobref     = NULL;
        struct iatt            stbuf      = {0,};
        struct iovec           vec        = {0,};

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        op_ret = cdp_fstat_with_gfid (this, pfd->fd, &stbuf, NULL);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "fstat failed on fd=%d: %s", pfd->fd,
                        strerror (op_errno));
                goto out;
        }

        iobref = iobref_new ();
        if (!iobref) {
                gf_log (this->name, GF_LOG_ERROR,
                        "Out of memory.");
                goto out;
        }

        iobuf = iobuf_get (this->ctx->iobuf_pool);
        if (!iobuf) {
                gf_log (this->name, GF_LOG_ERROR,
                        "Out of memory.");
                goto out;
        }

        trav_off = offset;
        trav_size = size;

        if (size > (stbuf.ia_size - offset))
                trav_size = stbuf.ia_size - offset;

        do {
                /* read block calculation is bit tricky */
                op_ret = get_read_block_size (pfd->snap_fd, pfd->fd_count,
                                              trav_off, trav_size, &tmp_size,
                                              &_fd);
                tmp_offset = trav_off;
                if (tmp_size <= trav_size)
                        eob_flag = 0;

                if (tmp_offset >= stbuf.ia_size) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "we are at the last block, send EOF");
                        op_ret = 0;
                        /* Hack to notify higher layers of EOF. */
                        op_errno = ENOENT;
                        goto done;
                }
                op_ret = lseek (_fd, tmp_offset, SEEK_SET);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "lseek(%"PRId64") failed: %s",
                                tmp_offset, strerror (op_errno));
                        goto out;
                }
                
                op_ret = read (_fd, iobuf->ptr + total_read, tmp_size);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "read failed on fd=%p: %s", pfd,
                                strerror (op_errno));
                        goto out;
                }

                trav_off   += op_ret;
                trav_size  -= op_ret;
                total_read += op_ret;

                LOCK (&priv->lock);
                {
                        priv->read_value    += op_ret;
                        //priv->interval_read += op_ret;
                }
                UNLOCK (&priv->lock);

                /* Hack to notify higher layers of EOF. */
                if (stbuf.ia_size == 0)
                        op_errno = ENOENT;
                else if ((tmp_offset + tmp_size) == stbuf.ia_size)
                        op_errno = ENOENT;

                if ((trav_size == 0) || (op_ret < tmp_size) ||
                    ((offset + total_read) >= stbuf.ia_size)) {
                        vec.iov_base = iobuf->ptr;
                        vec.iov_len  = total_read;
                        count++;

                        iobref_add (iobref, iobuf);

                        goto done;
                }
        } while ((!eob_flag) && (trav_size > 0));

        if (eob_flag) {
                gf_log (this->name, GF_LOG_CRITICAL,
                        "something very wrong.. :O");
                /* Just for completion */
                _fd = pfd->fd;
                op_ret = lseek (_fd, offset, SEEK_SET);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "lseek(%"PRId64") failed: %s",
                                tmp_offset, strerror (op_errno));
                        goto out;
                }

                op_ret = read (_fd, iobuf->ptr, size);
                if (op_ret == -1) {
                        op_errno = errno;
                        gf_log (this->name, GF_LOG_ERROR,
                                "read failed on fd=%p: %s", pfd,
                                strerror (op_errno));
                        goto out;
                }

                vec.iov_base = iobuf->ptr;
                vec.iov_len  = op_ret;
                total_read = op_ret;
                count++;

                iobref_add (iobref, iobuf);
        }

done:
        /*
         *  readv successful, and we need to get the stat of the file
         *  we read from
         */

        op_ret = cdp_fstat_with_gfid (this, pfd->fd, &stbuf, NULL);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "fstat failed on fd=%p: %s", pfd,
                        strerror (op_errno));
                goto out;
        }

        op_ret = total_read;
out:
        STACK_UNWIND_STRICT (readv, frame, op_ret, op_errno,
                             &vec, count, &stbuf, iobref);

        if (iobref)
                iobref_unref (iobref);
        if (iobuf)
                iobuf_unref (iobuf);

        return 0;
}

int
gf_snap_truncate_index (xlator_t *this, struct snap_fds *snap, off_t offset)
{
        int idx = 0;

        /* if offset is 0, that means, we have to start fresh with index */
        if (!snap)
                return 0;

        if (!offset) {
                snap->idx_len = 0;
                if (snap->snap_idx) {
                        snap->snap_idx[0].start = 0;
                        snap->snap_idx[0].size = 0;
                }
                goto out;
        }

        if (!snap->snap_idx) {
                snap->idx_len = 0;
                goto out;
        }

        /* Remove entries which starts after required offset */
        for (idx = 0; idx < snap->idx_len; idx++) {
                if (snap->snap_idx[idx].start >= offset) {
                        snap->idx_len--;
                        snap->snap_idx[idx].start =
                                snap->snap_idx[snap->idx_len].start;
                        snap->snap_idx[idx].size =
                                snap->snap_idx[snap->idx_len].size;
                        idx--; // check the currently put value again
                }
        }

        /* if there is a block which spans bigger than offset, make it proper */
        for (idx = 0; idx < snap->idx_len; idx++) {
                if (offset > (snap->snap_idx[idx].start +
                              snap->snap_idx[idx].size)) {
                        snap->snap_idx[idx].size = (offset -
                                                    snap->snap_idx[idx].start);
                }
        }

        if (snap->idx_len == 0) {
                snap->idx_len = 1;
                snap->snap_idx[0].start = offset;
                snap->snap_idx[0].size = 0;
        }

out:
        gf_sync_snap_info_file (snap);

        return 0;
}

int
gf_snap_writev_update_index (xlator_t *this, struct snap_fds *snap,
                             off_t offset, int32_t size)
{
        int temp_size = 0;
        int max_idx   = 0;
        int idx       = 0;

        max_idx = snap->idx_len;

        for (idx = 0; idx < max_idx; idx++) {
                /* Extending the previously written region */
                /*
                  |--------|
                           |--------|
                */
                if ((snap->snap_idx[idx].start +
                     snap->snap_idx[idx].size) == offset) {
                        snap->snap_idx[idx].size += size;
                        goto out;
                }

                /* Extending just the size */
                /*
                |---------|
                |-------------------|
                */
                if (snap->snap_idx[idx].start == offset) {
                        /* Same block gets overwritten with bigger data */
                        temp_size = (size - snap->snap_idx[idx].size);
                        if (temp_size > 0)
                                snap->snap_idx[idx].size = size;

                        goto out;
                }
                /* some of the write falls inside already
                   existing write.. */
                /*
                |----------|
                      |--------|
                */
                if ((snap->snap_idx[idx].start < offset) &&
                    ((snap->snap_idx[idx].start +
                      snap->snap_idx[idx].size) > offset)) {
                        /* This write falls in the already written
                         * region */
                        //gf_log ("", 1, "write-overlap");
                        temp_size = (size -
                                     ((snap->snap_idx[idx].start +
                                       snap->snap_idx[idx].size) -
                                      offset));
                        if (temp_size > 0)
                                snap->snap_idx[idx].size += temp_size;

                        goto out;
                }
        }

        snap->snap_idx[max_idx].start = offset;
        snap->snap_idx[max_idx].size  = size;
        snap->idx_len++;
        //if (!(snap->idx_len % 42))
        //        gf_sync_snap_info_file (pfd);

out:
        return 0;
}
