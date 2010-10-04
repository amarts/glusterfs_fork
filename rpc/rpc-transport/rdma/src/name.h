/*
  Copyright (c) 2008-2009 Gluster, Inc. <http://www.gluster.com>
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

#ifndef _IB_VERBS_NAME_H
#define _IB_VERBS_NAME_H

#include <sys/socket.h>
#include <sys/un.h>

#include "compat.h"

int32_t
gf_rdma_client_bind (rpc_transport_t *this,
                     struct sockaddr *sockaddr,
                     socklen_t *sockaddr_len,
                     int sock);

int32_t
gf_rdma_client_get_remote_sockaddr (rpc_transport_t *this,
                                    struct sockaddr *sockaddr,
                                    socklen_t *sockaddr_len,
                                    int16_t remote_port);

int32_t
gf_rdma_server_get_local_sockaddr (rpc_transport_t *this,
                                   struct sockaddr *addr,
                                   socklen_t *addr_len);

int32_t
gf_rdma_get_transport_identifiers (rpc_transport_t *this);

#endif /* _IB_VERBS_NAME_H */
