/*
   Copyright (c) 2020 Kadalu.IO <https://kadalu.io>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef __MARKER_QUOTA__
#define __MARKER_QUOTA__

typedef struct {
  gf_lock_t lock;
  pthread_t quota_set_thread;
  struct list_head ns_list;
} mq_private_t;

typedef struct {
  struct list_head priv_list; /* list of ns entris in private */
  inode_t *ns;                /* namespace inode */
  int64_t size;
  bool dirty;  
} mq_inode_t;

#endif /* __MARKER_QUOTA_H__ */
