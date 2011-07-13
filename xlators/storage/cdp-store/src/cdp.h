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

#ifndef _CDP_H_
#define _CDP_H_

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>

#ifdef linux
#ifdef __GLIBC__
#include <sys/fsuid.h>
#else
#include <unistd.h>
#endif
#endif

#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

#ifdef HAVE_SYS_EXTATTR_H
#include <sys/extattr.h>
#endif

#include "xlator.h"
#include "inode.h"
#include "compat.h"
#include "timer.h"
#include "cdp-mem-types.h"

/**
 * cdp_fd - internal structure common to file and directory fd's
 */

struct cdp_fd {
	int     fd;      /* fd returned by the kernel */
	int32_t flags;   /* flags for open/creat      */
	char *  path;    /* used by setdents/getdents */
	DIR *   dir;     /* handle returned by the kernel */
        int     flushwrites;
        struct list_head list; /* to add to the janitor list */
};


struct cdp_private {
	char   *base_path;
	int32_t base_path_length;

        gf_lock_t lock;

        char   *hostname;
        /* Statistics, provides activity of the server */

	struct timeval prev_fetch_time;
	struct timeval init_time;

	int64_t read_value;    /* Total read, from init */
	int64_t write_value;   /* Total write, from init */
        int64_t nr_files;
/*
   In some cases, two exported volumes may reside on the same
   partition on the server. Sending statvfs info for both
   the volumes will lead to erroneous df output at the client,
   since free space on the partition will be counted twice.

   In such cases, user can disable exporting statvfs info
   on one of the volumes by setting this option.
*/
	gf_boolean_t    export_statfs;

	gf_boolean_t    o_direct;     /* always open files in O_DIRECT mode */



        /* janitor thread which cleans up /.trash (created by replicate) */
        char *          trash_path;
};

#define CDP_BASE_PATH(this) (((struct cdp_private *)this->private)->base_path)

#define CDP_BASE_PATH_LEN(this) (((struct cdp_private *)this->private)->base_path_length)

#define MAKE_GFID_PATH(path,this,gfid)    do {                          \
                int     ret  = 0;                                       \
                int32_t dir1 = 0;                                       \
                int32_t dir2 = 0;                                       \
                struct stat tempbuf = {0,};                             \
                                                                        \
                if (uuid_is_null (gfid))                                \
                        break;                                          \
                                                                        \
                path = alloca (1024);                                   \
                dir1 = gfid[0] + ((int)(gfid[1] & 0x3f) << 8);          \
                dir2 = gfid[2] + ((int)(gfid[3] & 0x3f) << 8);          \
                snprintf (path, 1024, "%s/%d/%d/%s/type",               \
                          CDP_BASE_PATH(this),dir1,dir2,                \
                          uuid_utoa (gfid));                            \
                ret = stat (path, &tempbuf);                            \
                if (!ret && S_ISDIR (tempbuf.st_mode)) {                \
                        snprintf (path, 1024, "%s/%d/%d/%s/HEAD/",      \
                                  CDP_BASE_PATH(this),dir1,dir2,        \
                                  uuid_utoa (gfid));                    \
                } else {                                                \
                        snprintf (path, 1024, "%s/%d/%d/%s/HEAD/data",  \
                                  CDP_BASE_PATH(this),dir1,dir2,        \
                                  uuid_utoa (gfid));                    \
                }                                                       \
        } while(0)


/* Helper functions */
int setgid_override (xlator_t *this, char *real_path, gid_t *gid);
int cdp_gfid_set (xlator_t *this, const char *path, dict_t *xattr_req,
                  uuid_t gfid);
int cdp_fstat_with_gfid (xlator_t *this, int fd, struct iatt *stbuf_p,
                         uuid_t gfid);
int cdp_lstat_with_gfid (xlator_t *this, const char *path, struct iatt *buf,
                         uuid_t gfid);
dict_t *cdp_lookup_xattr_fill (xlator_t *this, const char *path,
                                 loc_t *loc, dict_t *xattr, struct iatt *buf);
int cdp_handle_pair (xlator_t *this, const char *real_path,
                       data_pair_t *trav, int flags);
int cdp_fhandle_pair (xlator_t *this, int fd, data_pair_t *trav, int flags);
int cdp_get_file_contents (xlator_t *this, const char *path,
                             const char *name, char **contents);
int cdp_set_file_contents (xlator_t *this, const char *path,
                             data_pair_t *trav, int flags);
int cdp_acl_xattr_set (xlator_t *this, const char *path, dict_t *xattr_req);
int cdp_entry_create_xattr_set (xlator_t *this, const char *path,
                                  dict_t *dict);
int is_gfid_dir_empty (xlator_t *this, const char *path);
int create_gfid_directory_path (xlator_t *this, uuid_t gfid, mode_t type);


#endif /* _CDP_H_ */
