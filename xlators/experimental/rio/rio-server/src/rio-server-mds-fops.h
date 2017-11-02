/*
  Copyright (c) 2017 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

/* File: rio-server-mds-fops.h
 * This file contains entry points for all RIO server/MDS FOPs
 */

#ifndef _RIO_SERVER_MDS_FOPS_H
#define _RIO_SERVER_MDS_FOPS_H

int32_t
rio_server_mds_lookup (call_frame_t *, xlator_t *, loc_t *, dict_t *);

int32_t
rio_server_create (call_frame_t *, xlator_t *, loc_t *, int32_t, mode_t,
                   mode_t, fd_t *, dict_t *);

int32_t
rio_server_mkdir (call_frame_t *, xlator_t *, loc_t *, mode_t,
                  mode_t, dict_t *);

int32_t
rio_server_mds_stat (call_frame_t *, xlator_t *, loc_t *, dict_t *);

int32_t
rio_server_mds_fstat (call_frame_t *, xlator_t *, fd_t *, dict_t *);

int32_t
rio_server_setattr (call_frame_t *, xlator_t *, loc_t *, struct iatt *,
                    int32_t, dict_t *);

int32_t
rio_server_fsetattr (call_frame_t *, xlator_t *, fd_t *, struct iatt *,
                     int32_t, dict_t *);

int32_t
rio_server_mds_truncate (call_frame_t *, xlator_t *, loc_t *, off_t, dict_t *);

#endif /* _RIO_SERVER_MDS_FOPS_H */
