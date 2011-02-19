/*
   Copyright (c) 2010 Gluster, Inc. <http://www.gluster.com>
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

#ifndef _LIBGLUSTERFSCLIENT_MEM_TYPES_H
#define _LIBGLUSTERFSCLIENT_MEM_TYPES_H

#include "mem-types.h"

#define GF_MEM_TYPE_START (gf_common_mt_end + 1)

enum glfs_mem_types_ {
        glfs_mt_session_t = GF_MEM_TYPE_START,
        glfs_mt_fd_t,
        glfs_mt_char,
        glfs_mt_call_pool_t,
        glfs_mt_xlator_t,
        glfs_mt_end

};
#endif
