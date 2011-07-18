/*
   Copyright (c) 2008-2010 Gluster, Inc. <http://www.gluster.com>
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

#ifndef __CDP_MEM_TYPES_H__
#define __CDP_MEM_TYPES_H__

#include "mem-types.h"

enum gf_cdp_mem_types_ {
        gf_cdp_mt_dir_entry_t = gf_common_mt_end + 1,
        gf_cdp_mt_cdp_fd,
        gf_cdp_mt_char,
        gf_cdp_mt_cdp_private,
        gf_cdp_mt_int32_t,
        gf_cdp_mt_cdp_dev_t,
        gf_cdp_mt_trash_path,
        gf_cdp_mt_snap_idx_t,
        gf_cdp_mt_end
};
#endif

