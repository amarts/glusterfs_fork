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
  int dummy;
} mq_private_t;

typedef struct {
  int64_t size;
  bool dirty;
} mq_inode_t;

#endif /* __MARKER_QUOTA_H__ */
