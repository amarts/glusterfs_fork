/*
  (C) 2006 Z RESEARCH Inc. <http://www.zresearch.com>
  
  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 2 of
  the License, or (at your option) any later version.
    
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.
    
  You should have received a copy of the GNU General Public
  License aint64_t with this program; if not, write to the Free
  Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301 USA
*/ 

#ifndef _UNIFY_H
#define _UNIFY_H

#include "scheduler.h"

#define MAX_DIR_ENTRY_STRING     (32 * 1024)

typedef struct cement_private {
  /* Update this structure depending on requirement */
  void *scheduler; /* THIS SHOULD BE THE FIRST VARIABLE, if xlator is using scheduler */
  struct sched_ops *sched_ops; /* Scheduler options */
  struct xlator **array; /* Child node array */
  struct xlator *lock_node;
  int32_t child_count;
  int32_t readdir_force_success;
} cement_private_t;

struct _unify_local_t {
  int32_t call_count;
  int32_t op_ret;
  int32_t op_errno;
  char *buf;
  mode_t mode;
  off_t offset;
  dev_t dev;
  uid_t uid;
  gid_t gid;
  int32_t flags;
  file_ctx_t *ctx;
  dict_t *file_ctx;
  dir_entry_t *entry;
  dir_entry_t *last;
  int32_t count;    // dir_entry_t count;
  struct stat stbuf;
  struct statvfs statvfs_buf;
  char *path;
  char *new_path;
  xlator_t *sched_xl;
  xlator_t *found_xl;
  call_frame_t *orig_frame;
};

typedef struct _unify_local_t unify_local_t;

#endif /* _UNIFY_H */
