/*
   Copyright (c) 2009-2009 Z RESEARCH, Inc. <http://www.zresearch.com>
   This file is part of GlusterFS.

   GlusterFS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published
   by the Free Software Foundation; either version 3 of the License,
   or (at your option) any later version.

   GlusterFS is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see
   <http://www.gnu.org/licenses/>.
*/


#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

/* TODO: add NS locking */

#include "glusterfs.h"
#include "xlator.h"
#include "dht-common.h"
#include "defaults.h"

#include <sys/time.h>

/* TODO:
   - use volumename in xattr instead of "dht"
   - use NS locks
   - handle all cases in self heal layout reconstruction
   - complete linkfile selfheal
*/


int
dht_lookup_selfheal_cbk (call_frame_t *frame, void *cookie,
			 xlator_t *this,
			 int op_ret, int op_errno)
{
	dht_local_t  *local = NULL;
	dht_layout_t *layout = NULL;
	int           ret = 0;

	local = frame->local;
	ret = op_ret;

	if (ret == 0) {
		layout = local->selfheal.layout;
		ret = inode_ctx_put (local->inode, this, 
                                     (uint64_t)(long)layout);

		if (ret == 0)
			local->selfheal.layout = NULL;
		
		if (local->st_ino) {
			local->stbuf.st_ino = local->st_ino;
		} else {
			gf_log (this->name, GF_LOG_DEBUG,
				"could not find hashed subvolume for %s",
				local->loc.path);
		}
	}

	DHT_STACK_UNWIND (frame, ret, local->op_errno, local->inode,
			  &local->stbuf, local->xattr);

	return 0;
}


int
dht_lookup_dir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int op_ret, int op_errno,
                    inode_t *inode, struct stat *stbuf, dict_t *xattr)
{
	dht_conf_t   *conf          = NULL;
        dht_local_t  *local         = NULL;
        int           this_call_cnt = 0;
        call_frame_t *prev          = NULL;
	dht_layout_t *layout        = NULL;
	int           ret           = 0;
	int           is_dir        = 0;

	conf  = this->private;
        local = frame->local;
        prev  = cookie;

	layout = local->layout;

        LOCK (&frame->lock);
        {
                /* TODO: assert equal mode on stbuf->st_mode and
		   local->stbuf->st_mode

		   else mkdir/chmod/chown and fix
		*/
		ret = dht_layout_merge (this, layout, prev->this,
					op_ret, op_errno, xattr);

		if (op_ret == -1) {
			local->op_errno = ENOENT;
			gf_log (this->name, GF_LOG_DEBUG,
				"lookup of %s on %s returned error (%s)",
				local->loc.path, prev->this->name,
				strerror (op_errno));

			goto unlock;
		}

 		is_dir = check_is_dir (inode, stbuf, xattr);
 		if (!is_dir) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "lookup of %s on %s returned non dir 0%o",
                                local->loc.path, prev->this->name,
                                stbuf->st_mode);
                        local->need_selfheal = 1;
 			goto unlock;
                }

 		local->op_ret = 0;
 		if (local->xattr == NULL)
 			local->xattr = dict_ref (xattr);
 		if (local->inode == NULL)
 			local->inode = inode_ref (inode);

		dht_stat_merge (this, &local->stbuf, stbuf, prev->this);

		if (prev->this == local->hashed_subvol)
			local->st_ino = local->stbuf.st_ino;

        }
unlock:
        UNLOCK (&frame->lock);


        this_call_cnt = dht_frame_return (frame);

        if (is_last_call (this_call_cnt)) {
                if (local->need_selfheal) {
                        local->need_selfheal = 0;
                        dht_lookup_everywhere (frame, this, &local->loc);
                        return 0;
                }

		if (local->op_ret == 0) {
			ret = dht_layout_normalize (this, &local->loc, layout);

			local->layout = NULL;

			if (ret != 0) {
				gf_log (this->name, GF_LOG_DEBUG,
					"fixing assignment on %s",
					local->loc.path);
				goto selfheal;
			}
			
			inode_ctx_put (local->inode, this,
                                       (uint64_t)(long)layout);
			
			if (local->st_ino) {
				local->stbuf.st_ino = local->st_ino;
			} else {
				gf_log (this->name, GF_LOG_DEBUG,
					"could not find hashed subvol for %s",
					local->loc.path);
			}
		}

		DHT_STACK_UNWIND (frame, local->op_ret, local->op_errno,
				  local->inode, &local->stbuf, local->xattr);
        }

	return 0;

selfheal:
	ret = dht_selfheal_directory (frame, dht_lookup_selfheal_cbk,
				      &local->loc, layout);

	return 0;
}

int
dht_revalidate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int op_ret, int op_errno,
                    inode_t *inode, struct stat *stbuf, dict_t *xattr)
{
        dht_local_t  *local         = NULL;
        int           this_call_cnt = 0;
        call_frame_t *prev          = NULL;
	dht_layout_t *layout        = NULL;
	dht_conf_t   *conf          = NULL;
	int           ret  = -1;
	int           is_dir = 0;
	int           is_linkfile = 0;

        local = frame->local;
        prev  = cookie;
	conf = this->private;

        LOCK (&frame->lock);
        {
		if (op_ret == -1) {
			local->op_errno = op_errno;

			if ((op_errno != ENOTCONN) 
                            && (op_errno != ENOENT)
                            && (op_errno != ESTALE)) {
				gf_log (this->name, GF_LOG_DEBUG,
					"subvolume %s returned -1 (%s)",
					prev->this->name, strerror (op_errno));
			}
                        
                        if (op_errno == ESTALE) {
                                /* propogate the ESTALE to parent. 
                                 * setting local->layout_mismatch would send
                                 * ESTALE to parent. */
                                local->layout_mismatch = 1;
                        }

			goto unlock;
		}

		if (S_IFMT & (stbuf->st_mode ^ local->inode->st_mode)) {
			gf_log (this->name, GF_LOG_DEBUG,
				"mismatching filetypes 0%o v/s 0%o for %s",
				(stbuf->st_mode & S_IFMT),
				(local->inode->st_mode & S_IFMT),
				local->loc.path);

			local->op_ret = -1;
			local->op_errno = EINVAL;

			goto unlock;
		}

		layout = dht_layout_get (this, inode);
		
		is_dir = check_is_dir (inode, stbuf, xattr);
		is_linkfile = check_is_linkfile (inode, stbuf, xattr);
		
		if (is_linkfile) {
			gf_log (this->name, GF_LOG_DEBUG,
				"linkfile found in revalidate for %s",
				local->loc.path);
			local->layout_mismatch = 1;

			goto unlock;
		}

		if (is_dir) {
			ret = dht_layout_dir_mismatch (this, layout,
						       prev->this, &local->loc,
						       xattr);
			if (ret != 0) {
				gf_log (this->name, GF_LOG_DEBUG,
					"mismatching layouts for %s", 
					local->loc.path);
			
				local->layout_mismatch = 1;

				goto unlock;
			}
		} 
		
		dht_stat_merge (this, &local->stbuf, stbuf, prev->this);
		
		local->op_ret = 0;
		local->stbuf.st_ino = local->st_ino;

		if (!local->xattr)
			local->xattr = dict_ref (xattr);
	}
unlock:
	UNLOCK (&frame->lock);

        this_call_cnt = dht_frame_return (frame);

        if (is_last_call (this_call_cnt)) {
		if (!S_ISDIR (local->stbuf.st_mode)
		    && (local->hashed_subvol != local->cached_subvol)
		    && (local->stbuf.st_nlink == 1)
		    && (conf->unhashed_sticky_bit)) {
			local->stbuf.st_mode |= S_ISVTX;
		}

		if (local->layout_mismatch) {
			local->op_ret = -1;
			local->op_errno = ESTALE;
		}
			
		DHT_STACK_UNWIND (frame, local->op_ret, local->op_errno,
				  local->inode, &local->stbuf, local->xattr);
	}

        return 0;
}


int
dht_lookup_linkfile_create_cbk (call_frame_t *frame, void *cookie,
				xlator_t *this,
				int32_t op_ret, int32_t op_errno,
				inode_t *inode, struct stat *stbuf)
{
	dht_local_t  *local = NULL;
	xlator_t     *cached_subvol = NULL;
	dht_conf_t   *conf = NULL;
        int           ret = -1;

	local = frame->local;
	cached_subvol = local->cached_subvol;
	conf = this->private;

        ret = dht_layout_inode_set (this, local->cached_subvol, inode);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "failed to set layout for subvolume %s",
                        cached_subvol ? cached_subvol->name : "<nil>");
                local->op_ret = -1;
                local->op_errno = EINVAL;
                goto unwind;
        }

	local->op_ret = 0;
	if ((local->stbuf.st_nlink == 1)
	    && (conf->unhashed_sticky_bit)) {
		local->stbuf.st_mode |= S_ISVTX;
	}

unwind:
	DHT_STACK_UNWIND (frame, local->op_ret, local->op_errno,
			  local->inode, &local->stbuf, local->xattr);
	return 0;
}


int
dht_lookup_everywhere_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
			   int32_t op_ret, int32_t op_errno,
			   inode_t *inode, struct stat *buf, dict_t *xattr)
{
	dht_conf_t   *conf          = NULL;
        dht_local_t  *local         = NULL;
        int           this_call_cnt = 0;
        call_frame_t *prev          = NULL;
	int           is_linkfile   = 0;
	int           is_dir        = 0;
	xlator_t     *subvol        = NULL;
	loc_t        *loc           = NULL;
	xlator_t     *link_subvol   = NULL;
	xlator_t     *hashed_subvol = NULL;
	xlator_t     *cached_subvol = NULL;
        int           ret = -1;

	conf   = this->private;

	local  = frame->local;
	loc    = &local->loc;

	prev   = cookie;
	subvol = prev->this;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			if (op_errno != ENOENT)
				local->op_errno = op_errno;
			goto unlock;
		}

		is_linkfile = check_is_linkfile (inode, buf, xattr);
		is_dir = check_is_dir (inode, buf, xattr);

		if (is_linkfile) {
			link_subvol = dht_linkfile_subvol (this, inode, buf,
							   xattr);
			gf_log (this->name, GF_LOG_DEBUG,
				"found on %s linkfile %s (-> %s)",
				subvol->name, loc->path,
				link_subvol ? link_subvol->name : "''");
			goto unlock;
		}

                if (is_dir) {
                        local->dir_count++;

                        gf_log (this->name, GF_LOG_DEBUG,
                                "found on %s directory %s",
                                subvol->name, loc->path);
                } else {
                        local->file_count++;

                        if (!local->cached_subvol) {
                                /* found one file */
                                dht_stat_merge (this, &local->stbuf, buf,
                                                subvol);
                                local->xattr = dict_ref (xattr);
                                local->cached_subvol = subvol;
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "found on %s file %s",
                                        subvol->name, loc->path);
                        } else {
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "multiple subvolumes (%s and %s) have "
                                        "file %s", local->cached_subvol->name,
                                        subvol->name, local->loc.path);
                        }
                }
	}
unlock:
	UNLOCK (&frame->lock);

	if (is_linkfile) {
		gf_log (this->name, GF_LOG_DEBUG,
			"deleting stale linkfile %s on %s",
			loc->path, subvol->name);
		dht_linkfile_unlink (frame, this, subvol, loc);
	}

	this_call_cnt = dht_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		hashed_subvol = local->hashed_subvol;
		cached_subvol = local->cached_subvol;

                if (local->file_count && local->dir_count) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "path %s exists as a file on one subvolume " 
                                "and directory on another. "
                                "Please fix it manually",
                                loc->path);
                        DHT_STACK_UNWIND (frame, -1, EIO, NULL, NULL, NULL);
                        return 0;
                }

                if (local->dir_count) {
                        dht_lookup_directory (frame, this, &local->loc);
                        return 0;
                }

		if (!cached_subvol) {
			DHT_STACK_UNWIND (frame, -1, ENOENT, NULL, NULL, NULL);
			return 0;
		}

                if (!hashed_subvol) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "cannot create linkfile file for %s on %s: "
                                "hashed subvolume cannot be found.",
                                loc->path, cached_subvol->name);
                        
                        local->op_ret = 0;
                        local->op_errno = 0;

                        ret = dht_layout_inode_set (frame->this, cached_subvol,
                                                    local->inode);
                        if (ret < 0) {
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "failed to set layout for subvol %s",
                                        cached_subvol ? cached_subvol->name :
                                        "<nil>");
                                local->op_ret = -1;
                                local->op_errno = EINVAL;
                        }

                        DHT_STACK_UNWIND (frame, local->op_ret,
                                          local->op_errno, local->inode,
                                          &local->stbuf, local->xattr);
                        return 0;
                }

                gf_log (this->name, GF_LOG_DEBUG,
                        "linking file %s existing on %s to %s (hash)",
                        loc->path, cached_subvol->name,
                        hashed_subvol->name);
                        
                dht_linkfile_create (frame, 
                                     dht_lookup_linkfile_create_cbk,
                                     cached_subvol, hashed_subvol, loc);
	}

	return 0;
}


int
dht_lookup_everywhere (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
	dht_conf_t     *conf = NULL;
	dht_local_t    *local = NULL;
	int             i = 0;
	int             call_cnt = 0;

	conf = this->private;
	local = frame->local;

	call_cnt = conf->subvolume_cnt;
	local->call_cnt = call_cnt;

	if (!local->inode)
		local->inode = inode_ref (loc->inode);

	for (i = 0; i < call_cnt; i++) {
		STACK_WIND (frame, dht_lookup_everywhere_cbk,
			    conf->subvolumes[i],
			    conf->subvolumes[i]->fops->lookup,
			    loc, local->xattr_req);
	}

	return 0;
}


int
dht_lookup_linkfile_cbk (call_frame_t *frame, void *cookie,
                         xlator_t *this, int op_ret, int op_errno,
                         inode_t *inode, struct stat *stbuf, dict_t *xattr)
{
        call_frame_t *prev = NULL;
	dht_local_t  *local = NULL;
	dht_layout_t *layout = NULL;
	xlator_t     *subvol = NULL;
	loc_t        *loc = NULL;
	dht_conf_t   *conf = NULL;

        prev   = cookie;
	subvol = prev->this;
	conf   = this->private;
	local  = frame->local;
	loc    = &local->loc;

        if (op_ret == -1) {
		gf_log (this->name, GF_LOG_DEBUG,
			"lookup of %s on %s (following linkfile) failed (%s)",
			local->loc.path, subvol->name, strerror (op_errno));
                goto err;
	}

        if (check_is_dir (inode, stbuf, xattr)) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "lookup of %s on %s (following linkfile) reached dir",
                        local->loc.path, subvol->name);
                goto err;
        }

        if (check_is_linkfile (inode, stbuf, xattr)) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "lookup of %s on %s (following linkfile) reached link",
                        local->loc.path, subvol->name);
                goto err;
        }

	if ((stbuf->st_nlink == 1)
	    && (conf->unhashed_sticky_bit)) {
		stbuf->st_mode |= S_ISVTX;
	}
        dht_itransform (this, prev->this, stbuf->st_ino, &stbuf->st_ino);

	layout = dht_layout_for_subvol (this, prev->this);
	if (!layout) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no pre-set layout for subvolume %s",
			prev->this->name);
		op_ret   = -1;
		op_errno = EINVAL;
		goto out;
	}

	inode_ctx_put (inode, this, (uint64_t)(long)layout);

out:
        DHT_STACK_UNWIND (frame, op_ret, op_errno, inode, stbuf, xattr);

        return 0;

err:
        dht_lookup_everywhere (frame, this, loc);

        return 0;
}


int
dht_lookup_directory (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
        int           call_cnt = 0;
        int           i = 0;
        dht_conf_t   *conf = NULL;
        dht_local_t  *local = NULL;

        conf = this->private;
        local = frame->local;

        call_cnt        = conf->subvolume_cnt;
        local->call_cnt = call_cnt;
		
        local->layout = dht_layout_new (this, conf->subvolume_cnt);
        if (!local->layout) {
                gf_log (this->name, GF_LOG_ERROR,
                        "Out of memory");
                DHT_STACK_UNWIND (frame, -1, ENOMEM, NULL, NULL, NULL);
                return 0;
        }
		
        for (i = 0; i < call_cnt; i++) {
                STACK_WIND (frame, dht_lookup_dir_cbk,
                            conf->subvolumes[i],
                            conf->subvolumes[i]->fops->lookup,
                            &local->loc, local->xattr_req);
        }
        return 0;
}


int
dht_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno,
                inode_t *inode, struct stat *stbuf, dict_t *xattr)
{
	dht_layout_t *layout      = NULL;
        char          is_linkfile = 0;
        char          is_dir      = 0;
        xlator_t     *subvol      = NULL;
        dht_conf_t   *conf        = NULL;
        dht_local_t  *local       = NULL;
        loc_t        *loc         = NULL;
        call_frame_t *prev        = NULL;


        conf  = this->private;

        prev  = cookie;
        local = frame->local;
        loc   = &local->loc;

	if (ENTRY_MISSING (op_ret, op_errno)) {
		if (conf->search_unhashed) {
			local->op_errno = ENOENT;
			dht_lookup_everywhere (frame, this, loc);
			return 0;
		}
	}

 	if (op_ret == 0) {
 		is_dir      = check_is_dir (inode, stbuf, xattr);
 		if (is_dir) {
 			local->inode = inode_ref (inode);
 			local->xattr = dict_ref (xattr);
 		}
 	}

 	if (is_dir || (op_ret == -1 && op_errno == ENOTCONN)) {
                dht_lookup_directory (frame, this, &local->loc);
                return 0;
 	}
 
        if (op_ret == -1)
                goto out;

        is_linkfile = check_is_linkfile (inode, stbuf, xattr);
        is_dir      = check_is_dir (inode, stbuf, xattr);

        if (!is_dir && !is_linkfile) {
                /* non-directory and not a linkfile */

		dht_itransform (this, prev->this, stbuf->st_ino,
				&stbuf->st_ino);

		layout = dht_layout_for_subvol (this, prev->this);
		if (!layout) {
			gf_log (this->name, GF_LOG_DEBUG,
				"no pre-set layout for subvolume %s",
				prev->this->name);
			op_ret   = -1;
			op_errno = EINVAL;
			goto out;
		}

                inode_ctx_put (inode, this, (uint64_t)(long)layout);
                goto out; 
	}

        if (is_linkfile) {
                subvol = dht_linkfile_subvol (this, inode, stbuf, xattr);

                if (!subvol) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "linkfile not having link subvolume. path=%s",
                                loc->path);
			dht_lookup_everywhere (frame, this, loc);
			return 0;
                }

		STACK_WIND (frame, dht_lookup_linkfile_cbk,
			    subvol, subvol->fops->lookup,
			    &local->loc, local->xattr_req);
        }

        return 0;

out:
        DHT_STACK_UNWIND (frame, op_ret, op_errno, inode, stbuf, xattr);
        return 0;
}


int
dht_lookup (call_frame_t *frame, xlator_t *this,
            loc_t *loc, dict_t *xattr_req)
{
        xlator_t     *subvol = NULL;
        xlator_t     *hashed_subvol = NULL;
        xlator_t     *cached_subvol = NULL;
        dht_local_t  *local  = NULL;
	dht_conf_t   *conf = NULL;
        int           ret    = -1;
        int           op_errno = -1;
	dht_layout_t *layout = NULL;
	int           i = 0;
	int           call_cnt = 0;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	conf = this->private;

        local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

        ret = loc_dup (loc, &local->loc);
        if (ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_DEBUG,
                        "copying location failed for path=%s",
                        loc->path);
                goto err;
        }
	
	if (xattr_req) {
		local->xattr_req = dict_ref (xattr_req);
	} else {
		local->xattr_req = dict_new ();
	}

	hashed_subvol = dht_subvol_get_hashed (this, loc);
	cached_subvol = dht_subvol_get_cached (this, loc->inode);

	local->cached_subvol = cached_subvol;
	local->hashed_subvol = hashed_subvol;

        if (is_revalidate (loc)) {
		layout = dht_layout_get (this, loc->inode);

                if (!layout) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "revalidate without cache. path=%s",
                                loc->path);
                        op_errno = EINVAL;
                        goto err;
                }

		if (layout->gen && (layout->gen < conf->gen)) {
			gf_log (this->name, GF_LOG_TRACE,
				"incomplete layout failure for path=%s",
				loc->path);
			op_errno = ESTALE;
			goto err;
		}

		local->inode    = inode_ref (loc->inode);
		local->st_ino   = loc->inode->ino;
		
		local->call_cnt = layout->cnt;
		call_cnt = local->call_cnt;
		
		/* NOTE: we don't require 'trusted.glusterfs.dht.linkto' attribute,
		 *       revalidates directly go to the cached-subvolume.
		 */
		ret = dict_set_uint32 (local->xattr_req, 
				       "trusted.glusterfs.dht", 4 * 4);

		for (i = 0; i < layout->cnt; i++) {
			subvol = layout->list[i].xlator;
			
			STACK_WIND (frame, dht_revalidate_cbk,
				    subvol, subvol->fops->lookup,
				    loc, local->xattr_req);

			if (!--call_cnt)
				break;
		}
        } else {
		/* TODO: remove the hard-coding */
		ret = dict_set_uint32 (local->xattr_req, 
				       "trusted.glusterfs.dht", 4 * 4);

		ret = dict_set_uint32 (local->xattr_req, 
				       "trusted.glusterfs.dht.linkto", 256);

                if (!hashed_subvol) {
			gf_log (this->name, GF_LOG_DEBUG,
				"no subvolume in layout for path=%s, "
				"checking on all the subvols to see if "
				"it is a directory", loc->path);
 			call_cnt        = conf->subvolume_cnt;
 			local->call_cnt = call_cnt;
 			
 			local->layout = dht_layout_new (this, conf->subvolume_cnt);
 			if (!local->layout) {
 				op_errno = ENOMEM;
 				gf_log (this->name, GF_LOG_ERROR,
 					"Out of memory");
 				goto err;
 			}

			for (i = 0; i < call_cnt; i++) {
 				STACK_WIND (frame, dht_lookup_dir_cbk,
 					    conf->subvolumes[i],
 					    conf->subvolumes[i]->fops->lookup,
 					    &local->loc, local->xattr_req);
 			}
 			return 0;
                }

                STACK_WIND (frame, dht_lookup_cbk,
                            hashed_subvol, hashed_subvol->fops->lookup,
                            loc, local->xattr_req);
        }

        return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
        DHT_STACK_UNWIND (frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}


int
dht_attr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
	      int op_ret, int op_errno, struct stat *stbuf)
{
	dht_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;


	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}

		dht_stat_merge (this, &local->stbuf, stbuf, prev->this);
		
		if (local->inode)
			local->stbuf.st_ino = local->inode->ino;
		local->op_ret = 0;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = dht_frame_return (frame);
	if (is_last_call (this_call_cnt))
		DHT_STACK_UNWIND (frame, local->op_ret, local->op_errno,
				  &local->stbuf);

        return 0;
}


int
dht_stat (call_frame_t *frame, xlator_t *this,
	  loc_t *loc)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;
	dht_local_t  *local = NULL;
	dht_layout_t *layout = NULL;
	int           i = 0;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	layout = dht_layout_get (this, loc->inode);
	if (!layout) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no layout for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->inode = inode_ref (loc->inode);
	local->call_cnt = layout->cnt;

	for (i = 0; i < layout->cnt; i++) {
		subvol = layout->list[i].xlator;

		STACK_WIND (frame, dht_attr_cbk,
			    subvol, subvol->fops->stat,
			    loc);
	}

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_fstat (call_frame_t *frame, xlator_t *this,
	   fd_t *fd)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;
	dht_local_t  *local = NULL;
	dht_layout_t *layout = NULL;
	int           i = 0;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	layout = dht_layout_get (this, fd->inode);
	if (!layout) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no layout for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->inode    = inode_ref (fd->inode);
	local->call_cnt = layout->cnt;;

	for (i = 0; i < layout->cnt; i++) {
		subvol = layout->list[i].xlator;
		STACK_WIND (frame, dht_attr_cbk,
			    subvol, subvol->fops->fstat,
			    fd);
	}

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_truncate (call_frame_t *frame, xlator_t *this,
	      loc_t *loc, off_t offset)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;
	dht_local_t  *local = NULL;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	subvol = dht_subvol_get_cached (this, loc->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->inode = inode_ref (loc->inode);
	local->call_cnt = 1;

	STACK_WIND (frame, dht_attr_cbk,
		    subvol, subvol->fops->truncate,
		    loc, offset);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_ftruncate (call_frame_t *frame, xlator_t *this,
	       fd_t *fd, off_t offset)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;
	dht_local_t  *local = NULL;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	subvol = dht_subvol_get_cached (this, fd->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->inode = inode_ref (fd->inode);
	local->call_cnt = 1;

	STACK_WIND (frame, dht_attr_cbk,
		    subvol, subvol->fops->ftruncate,
		    fd, offset);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_err_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
	     int op_ret, int op_errno)
{
	dht_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;


	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}

		local->op_ret = 0;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = dht_frame_return (frame);
	if (is_last_call (this_call_cnt))
		DHT_STACK_UNWIND (frame, local->op_ret, local->op_errno);

        return 0;
}


int
dht_access (call_frame_t *frame, xlator_t *this,
	    loc_t *loc, int32_t mask)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;
	dht_local_t  *local = NULL;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	subvol = dht_subvol_get_cached (this, loc->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->call_cnt = 1;

	STACK_WIND (frame, dht_err_cbk,
		    subvol, subvol->fops->access,
		    loc, mask);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno);

	return 0;
}


int
dht_readlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		  int op_ret, int op_errno, const char *path)
{
        DHT_STACK_UNWIND (frame, op_ret, op_errno, path);

        return 0;
}


int
dht_readlink (call_frame_t *frame, xlator_t *this,
	      loc_t *loc, size_t size)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	subvol = dht_subvol_get_cached (this, loc->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	STACK_WIND (frame, dht_readlink_cbk,
		    subvol, subvol->fops->readlink,
		    loc, size);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_getxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		  int op_ret, int op_errno, dict_t *xattr)
{
        DHT_STACK_UNWIND (frame, op_ret, op_errno, xattr);

        return 0;
}


int
dht_getxattr (call_frame_t *frame, xlator_t *this,
	      loc_t *loc, const char *key)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	subvol = dht_subvol_get_cached (this, loc->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	STACK_WIND (frame, dht_getxattr_cbk,
		    subvol, subvol->fops->getxattr,
		    loc, key);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_setxattr (call_frame_t *frame, xlator_t *this,
	      loc_t *loc, dict_t *xattr, int flags)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;
	dht_local_t  *local = NULL;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	subvol = dht_subvol_get_cached (this, loc->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->call_cnt = 1;

	STACK_WIND (frame, dht_err_cbk,
		    subvol, subvol->fops->setxattr,
		    loc, xattr, flags);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_removexattr (call_frame_t *frame, xlator_t *this,
		 loc_t *loc, const char *key)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;
	dht_local_t  *local = NULL;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	subvol = dht_subvol_get_cached (this, loc->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->call_cnt = 1;

	STACK_WIND (frame, dht_err_cbk,
		    subvol, subvol->fops->removexattr,
		    loc, key);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_fd_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
	      int op_ret, int op_errno, fd_t *fd)
{
	dht_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;


	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}

		local->op_ret = 0;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = dht_frame_return (frame);
	if (is_last_call (this_call_cnt))
		DHT_STACK_UNWIND (frame, local->op_ret, local->op_errno,
				  local->fd);

        return 0;
}


int
dht_open (call_frame_t *frame, xlator_t *this,
	  loc_t *loc, int flags, fd_t *fd)
{
	xlator_t     *subvol = NULL;
	int           ret = -1;
        int           op_errno = -1;
	dht_local_t  *local = NULL;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	subvol = dht_subvol_get_cached (this, fd->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->fd = fd_ref (fd);
	ret = loc_dup (loc, &local->loc);
	if (ret == -1) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->call_cnt = 1;

	STACK_WIND (frame, dht_fd_cbk,
		    subvol, subvol->fops->open,
		    loc, flags, fd);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
	       int op_ret, int op_errno,
	       struct iovec *vector, int count, struct stat *stbuf,
               struct iobref *iobref)
{
        DHT_STACK_UNWIND (frame, op_ret, op_errno, vector, count, stbuf,
                          iobref);

        return 0;
}


int
dht_readv (call_frame_t *frame, xlator_t *this,
	   fd_t *fd, size_t size, off_t off)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	subvol = dht_subvol_get_cached (this, fd->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}

	STACK_WIND (frame, dht_readv_cbk,
		    subvol, subvol->fops->readv,
		    fd, size, off);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL, 0, NULL, NULL);

	return 0;
}


int
dht_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno, struct stat *stbuf)
{
        DHT_STACK_UNWIND (frame, op_ret, op_errno, stbuf);

        return 0;
}


int
dht_writev (call_frame_t *frame, xlator_t *this,
	    fd_t *fd, struct iovec *vector, int count, off_t off,
            struct iobref *iobref)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	subvol = dht_subvol_get_cached (this, fd->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}

	STACK_WIND (frame, dht_writev_cbk,
		    subvol, subvol->fops->writev,
		    fd, vector, count, off, iobref);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL, 0);

	return 0;
}


int
dht_flush (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;
	dht_local_t  *local = NULL;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	subvol = dht_subvol_get_cached (this, fd->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->fd = fd_ref (fd);
	local->call_cnt = 1;

	STACK_WIND (frame, dht_err_cbk,
		    subvol, subvol->fops->flush, fd);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno);

	return 0;
}


int
dht_fsync (call_frame_t *frame, xlator_t *this,
	   fd_t *fd, int datasync)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;
	dht_local_t  *local = NULL;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	subvol = dht_subvol_get_cached (this, fd->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}
	local->call_cnt = 1;

	STACK_WIND (frame, dht_err_cbk,
		    subvol, subvol->fops->fsync,
		    fd, datasync);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno);

	return 0;
}


int
dht_lk_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
	    int op_ret, int op_errno, struct flock *flock)
{
        DHT_STACK_UNWIND (frame, op_ret, op_errno, flock);

        return 0;
}


int
dht_lk (call_frame_t *frame, xlator_t *this,
	fd_t *fd, int cmd, struct flock *flock)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	subvol = dht_subvol_get_cached (this, fd->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}

	STACK_WIND (frame, dht_lk_cbk,
		    subvol, subvol->fops->lk,
		    fd, cmd, flock);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_statfs_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno, struct statvfs *statvfs)
{
	dht_local_t  *local = NULL;
	int           this_call_cnt = 0;


	local = frame->local;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			goto unlock;
		}
		local->op_ret = 0;

		/* TODO: normalize sizes */
		local->statvfs.f_bsize    = statvfs->f_bsize;
		local->statvfs.f_frsize   = statvfs->f_frsize;

		local->statvfs.f_blocks  += statvfs->f_blocks;
		local->statvfs.f_bfree   += statvfs->f_bfree;
		local->statvfs.f_bavail  += statvfs->f_bavail;
		local->statvfs.f_files   += statvfs->f_files;
		local->statvfs.f_ffree   += statvfs->f_ffree;
		local->statvfs.f_favail  += statvfs->f_favail;
		local->statvfs.f_fsid     = statvfs->f_fsid;
		local->statvfs.f_flag     = statvfs->f_flag;
		local->statvfs.f_namemax  = statvfs->f_namemax;

	}
unlock:
	UNLOCK (&frame->lock);


	this_call_cnt = dht_frame_return (frame);
	if (is_last_call (this_call_cnt))
		DHT_STACK_UNWIND (frame, local->op_ret, local->op_errno,
				  &local->statvfs);

        return 0;
}


int
dht_statfs (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
	dht_local_t  *local  = NULL;
	dht_conf_t   *conf = NULL;
        int           op_errno = -1;
	int           i = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	conf = this->private;

	local = dht_local_init (frame);
	local->call_cnt = conf->subvolume_cnt;

	for (i = 0; i < conf->subvolume_cnt; i++) {
		STACK_WIND (frame, dht_statfs_cbk,
			    conf->subvolumes[i],
			    conf->subvolumes[i]->fops->statfs, loc);
	}

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_opendir (call_frame_t *frame, xlator_t *this, loc_t *loc, fd_t *fd)
{
	dht_local_t  *local  = NULL;
	dht_conf_t   *conf = NULL;
	int           ret = -1;
        int           op_errno = -1;
	int           i = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	conf = this->private;

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->fd = fd_ref (fd);
	ret = loc_dup (loc, &local->loc);
	if (ret == -1) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->call_cnt = conf->subvolume_cnt;

	for (i = 0; i < conf->subvolume_cnt; i++) {
		STACK_WIND (frame, dht_fd_cbk,
			    conf->subvolumes[i],
			    conf->subvolumes[i]->fops->opendir,
			    loc, fd);
	}

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_readdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		 int op_ret, int op_errno, gf_dirent_t *orig_entries)
{
	dht_local_t  *local = NULL;
	gf_dirent_t   entries;
	gf_dirent_t  *orig_entry = NULL;
	gf_dirent_t  *entry = NULL;
	call_frame_t *prev = NULL;
	xlator_t     *next_subvol = NULL;
        off_t         next_offset = 0;
	int           count = 0;


	INIT_LIST_HEAD (&entries.list);
	prev = cookie;
	local = frame->local;

	if (op_ret < 0)
		goto done;

	list_for_each_entry (orig_entry, (&orig_entries->list), list) {
                next_offset = orig_entry->d_off;

                if (check_is_linkfile (NULL, (&orig_entry->d_stat), NULL)
                    || (check_is_dir (NULL, (&orig_entry->d_stat), NULL)
                        && (prev->this != dht_first_up_subvol (this)))) {
                        continue;
                }

                entry = gf_dirent_for_name (orig_entry->d_name);
                if (!entry) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "Out of memory");
                        goto unwind;
                }

                dht_itransform (this, prev->this, orig_entry->d_ino,
                                &entry->d_ino);
                dht_itransform (this, prev->this, orig_entry->d_off,
                                &entry->d_off);

                entry->d_type = orig_entry->d_type;
                entry->d_len  = orig_entry->d_len;

                list_add_tail (&entry->list, &entries.list);
                count++;
	}
	op_ret = count;

done:
	if (count == 0) {
                /* non-zero next_offset means that
                   EOF is not yet hit on the current subvol
                */
                if (next_offset == 0) {
                        next_subvol = dht_subvol_next (this, prev->this);
                } else {
                        next_subvol = prev->this;
                }

		if (!next_subvol) {
			goto unwind;
		}

		STACK_WIND (frame, dht_readdir_cbk,
			    next_subvol, next_subvol->fops->readdir,
			    local->fd, local->size, next_offset);
		return 0;
	}

unwind:
	if (op_ret < 0)
		op_ret = 0;

	DHT_STACK_UNWIND (frame, op_ret, op_errno, &entries);

	gf_dirent_free (&entries);

        return 0;
}


int
dht_readdir (call_frame_t *frame, xlator_t *this,
	     fd_t *fd, size_t size, off_t yoff)
{
	dht_local_t  *local  = NULL;
	dht_conf_t   *conf = NULL;
        int           op_errno = -1;
	xlator_t     *xvol = NULL;
	off_t         xoff = 0;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	conf = this->private;

	local = dht_local_init (frame);
	if (!local) {
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	local->fd = fd_ref (fd);
	local->size = size;

	dht_deitransform (this, yoff, &xvol, (uint64_t *)&xoff);

	/* TODO: do proper readdir */
	STACK_WIND (frame, dht_readdir_cbk,
		    xvol, xvol->fops->readdir,
		    fd, size, xoff);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_fsyncdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		  int op_ret, int op_errno)
{
	dht_local_t  *local = NULL;
	int           this_call_cnt = 0;


	local = frame->local;

	LOCK (&frame->lock);
	{
		if (op_ret == -1)
			local->op_errno = op_errno;

		if (op_ret == 0)
			local->op_ret = 0;
	}
	UNLOCK (&frame->lock);

	this_call_cnt = dht_frame_return (frame);
	if (is_last_call (this_call_cnt))
		DHT_STACK_UNWIND (frame, local->op_ret, local->op_errno);

        return 0;
}


int
dht_fsyncdir (call_frame_t *frame, xlator_t *this, fd_t *fd, int datasync)
{
	dht_local_t  *local  = NULL;
	dht_conf_t   *conf = NULL;
        int           op_errno = -1;
	int           i = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	conf = this->private;

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->fd = fd_ref (fd);
	local->call_cnt = conf->subvolume_cnt;

	for (i = 0; i < conf->subvolume_cnt; i++) {
		STACK_WIND (frame, dht_fsyncdir_cbk,
			    conf->subvolumes[i],
			    conf->subvolumes[i]->fops->fsyncdir,
			    fd, datasync);
	}

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno);

	return 0;
}


int
dht_newfile_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		 int op_ret, int op_errno,
		 inode_t *inode, struct stat *stbuf)
{
	call_frame_t *prev = NULL;
	dht_layout_t *layout = NULL;
	int           ret = -1;


	if (op_ret == -1)
		goto out;

	prev = cookie;

	dht_itransform (this, prev->this, stbuf->st_ino, &stbuf->st_ino);
	layout = dht_layout_for_subvol (this, prev->this);

	if (!layout) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no pre-set layout for subvolume %s",
			prev->this->name);
		op_ret   = -1;
		op_errno = EINVAL;
		goto out;
	}

	ret = inode_ctx_put (inode, this, (uint64_t)(long)layout);
	if (ret != 0) {
		gf_log (this->name, GF_LOG_DEBUG,
			"could not set inode context");
		op_ret   = -1;
		op_errno = EINVAL;
		goto out;
	}

out:
	DHT_STACK_UNWIND (frame, op_ret, op_errno, inode, stbuf);
	return 0;
}

int
dht_mknod_linkfile_create_cbk (call_frame_t *frame, void *cookie,
                               xlator_t *this,
                               int32_t op_ret, int32_t op_errno,
                               inode_t *inode, struct stat *stbuf)
{
	dht_local_t  *local = NULL;
	xlator_t     *cached_subvol = NULL;

        if (op_ret == -1)
                goto err;

	local = frame->local;
	cached_subvol = local->cached_subvol;

        STACK_WIND (frame, dht_newfile_cbk,
                    cached_subvol, cached_subvol->fops->mknod,
                    &local->loc, local->mode, local->rdev);

        return 0;
 err:
 	DHT_STACK_UNWIND (frame, -1, op_errno, NULL, NULL);	
 	return 0;
}

int
dht_mknod (call_frame_t *frame, xlator_t *this,
	   loc_t *loc, mode_t mode, dev_t rdev)
{
	xlator_t    *subvol = NULL;
	int          op_errno = -1;
        int          ret = -1;
        xlator_t    *avail_subvol = NULL;
	dht_conf_t  *conf = NULL;
	dht_local_t *local = NULL;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (loc, err);

	conf = this->private;

        dht_get_du_info (frame, this, loc);

	subvol = dht_subvol_get_hashed (this, loc);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no subvolume in layout for path=%s",
			loc->path);
		op_errno = ENOENT;
		goto err;
	}

        if (!dht_is_subvol_filled (this, subvol)) {
                gf_log (this->name, GF_LOG_TRACE,
                        "creating %s on %s", loc->path, subvol->name);
                
                STACK_WIND (frame, dht_newfile_cbk,
                            subvol, subvol->fops->mknod,
                            loc, mode, rdev);
        } else {
                avail_subvol = dht_free_disk_available_subvol (this, subvol);
                if (avail_subvol != subvol) {
                        /* Choose the minimum filled volume, and create the 
                           files there */
                        local = dht_local_init (frame);
                        if (!local) {
                                op_errno = ENOMEM;
                                gf_log (this->name, GF_LOG_ERROR,
                                        "Out of memory");
                                goto err;
                        }
                        ret = loc_dup (loc, &local->loc);
                        if (ret == -1) {
                                op_errno = ENOMEM;
                                gf_log (this->name, GF_LOG_ERROR,
                                        "Out of memory");
                                goto err;
                        }

                        local->cached_subvol = avail_subvol;
                        local->mode = mode; 
                        local->rdev = rdev;
                        
                        dht_linkfile_create (frame, 
                                             dht_mknod_linkfile_create_cbk,
                                             avail_subvol, subvol, loc);
                } else {
                        gf_log (this->name, GF_LOG_TRACE,
                                "creating %s on %s", loc->path, subvol->name);
                        
                        STACK_WIND (frame, dht_newfile_cbk,
                                    subvol, subvol->fops->mknod,
                                    loc, mode, rdev);
                }
        }

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL, NULL);

	return 0;
}


int
dht_symlink (call_frame_t *frame, xlator_t *this,
	     const char *linkname, loc_t *loc)
{
	xlator_t  *subvol = NULL;
	int        op_errno = -1;


	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (loc, err);

	subvol = dht_subvol_get_hashed (this, loc);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no subvolume in layout for path=%s",
			loc->path);
		op_errno = ENOENT;
		goto err;
	}

	gf_log (this->name, GF_LOG_TRACE,
		"creating %s on %s", loc->path, subvol->name);

	STACK_WIND (frame, dht_newfile_cbk,
		    subvol, subvol->fops->symlink,
		    linkname, loc);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL, NULL);

	return 0;
}


int
dht_unlink (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
	xlator_t    *cached_subvol = NULL;
	xlator_t    *hashed_subvol = NULL;
	int          op_errno = -1;
	dht_local_t *local = NULL;


	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (loc, err);

	cached_subvol = dht_subvol_get_cached (this, loc->inode);
	if (!cached_subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	hashed_subvol = dht_subvol_get_hashed (this, loc);
	if (!hashed_subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no subvolume in layout for path=%s",
			loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->call_cnt = 1;
	if (hashed_subvol != cached_subvol)
		local->call_cnt++;

	STACK_WIND (frame, dht_err_cbk,
		    cached_subvol, cached_subvol->fops->unlink, loc);

	if (hashed_subvol != cached_subvol)
		STACK_WIND (frame, dht_err_cbk,
			    hashed_subvol, hashed_subvol->fops->unlink, loc);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno);

	return 0;
}


int
dht_link_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
	      int op_ret, int op_errno,
	      inode_t *inode, struct stat *stbuf)
{
        call_frame_t *prev = NULL;
	dht_layout_t *layout = NULL;
	dht_local_t  *local = NULL;

        prev = cookie;
	local = frame->local;

        if (op_ret == -1)
                goto out;

	layout = dht_layout_for_subvol (this, prev->this);
	if (!layout) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no pre-set layout for subvolume %s",
			prev->this->name);
		op_ret   = -1;
		op_errno = EINVAL;
		goto out;
	}

	stbuf->st_ino = local->loc.inode->ino;

out:
        DHT_STACK_UNWIND (frame, op_ret, op_errno, inode, stbuf);

	return 0;
}


int
dht_link_linkfile_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		       int op_ret, int op_errno,
		       inode_t *inode, struct stat *stbuf)
{
	dht_local_t  *local = NULL;
	xlator_t     *srcvol = NULL;


	if (op_ret == -1)
		goto err;

	local = frame->local;
	srcvol = local->linkfile.srcvol;

	STACK_WIND (frame, dht_link_cbk,
		    srcvol, srcvol->fops->link,
		    &local->loc, &local->loc2);

	return 0;

err:
	DHT_STACK_UNWIND (frame, op_ret, op_errno, inode, stbuf);

	return 0;
}


int
dht_link (call_frame_t *frame, xlator_t *this,
	  loc_t *oldloc, loc_t *newloc)
{
	xlator_t    *cached_subvol = NULL;
	xlator_t    *hashed_subvol = NULL;
	int          op_errno = -1;
	int          ret = -1;
	dht_local_t *local = NULL;


	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (oldloc, err);
	VALIDATE_OR_GOTO (newloc, err);

	cached_subvol = dht_subvol_get_cached (this, oldloc->inode);
	if (!cached_subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for path=%s", oldloc->path);
		op_errno = EINVAL;
		goto err;
	}

	hashed_subvol = dht_subvol_get_hashed (this, newloc);
	if (!hashed_subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no subvolume in layout for path=%s",
			newloc->path);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	ret = loc_copy (&local->loc, oldloc);
	if (ret == -1) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	ret = loc_copy (&local->loc2, newloc);
	if (ret == -1) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	if (hashed_subvol != cached_subvol) {
		dht_linkfile_create (frame, dht_link_linkfile_cbk,
				     cached_subvol, hashed_subvol, newloc);
	} else {
		STACK_WIND (frame, dht_link_cbk,
			    cached_subvol, cached_subvol->fops->link,
			    oldloc, newloc);
	}

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL, NULL);

	return 0;
}


int
dht_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		 int op_ret, int op_errno,
		 fd_t *fd, inode_t *inode, struct stat *stbuf)
{
	call_frame_t *prev = NULL;
	dht_layout_t *layout = NULL;
	int           ret = -1;

	if (op_ret == -1)
		goto out;

	prev = cookie;

	dht_itransform (this, prev->this, stbuf->st_ino, &stbuf->st_ino);
	layout = dht_layout_for_subvol (this, prev->this);

	if (!layout) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no pre-set layout for subvolume %s",
			prev->this->name);
		op_ret   = -1;
		op_errno = EINVAL;
		goto out;
	}

	ret = inode_ctx_put (inode, this, (uint64_t)(long)layout);
	if (ret != 0) {
		gf_log (this->name, GF_LOG_DEBUG,
			"could not set inode context");
		op_ret   = -1;
		op_errno = EINVAL;
		goto out;
	}

out:
	DHT_STACK_UNWIND (frame, op_ret, op_errno, fd, inode, stbuf);
	return 0;
}


int
dht_create_linkfile_create_cbk (call_frame_t *frame, void *cookie,
				xlator_t *this,
				int32_t op_ret, int32_t op_errno,
				inode_t *inode, struct stat *stbuf)
{
	dht_local_t  *local = NULL;
	xlator_t     *cached_subvol = NULL;

        if (op_ret == -1)
                goto err;

	local = frame->local;
	cached_subvol = local->cached_subvol;

        STACK_WIND (frame, dht_create_cbk,
                    cached_subvol, cached_subvol->fops->create,
                    &local->loc, local->flags, local->mode, local->fd);

        return 0;
 err:
 	DHT_STACK_UNWIND (frame, -1, op_errno, NULL, NULL, NULL);	
 	return 0;
}

int
dht_create (call_frame_t *frame, xlator_t *this,
	    loc_t *loc, int32_t flags, mode_t mode, fd_t *fd)
{
	int          op_errno = -1;
        int          ret = -1;
	xlator_t    *subvol = NULL;
	dht_conf_t  *conf = NULL;
        dht_local_t *local = NULL;
        xlator_t    *avail_subvol = NULL;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (loc, err);

	conf = this->private;

        dht_get_du_info (frame, this, loc);

	local = dht_local_init (frame);
	if (!local) {
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	subvol = dht_subvol_get_hashed (this, loc);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no subvolume in layout for path=%s",
			loc->path);
		op_errno = ENOENT;
		goto err;
	}

        if (!dht_is_subvol_filled (this, subvol)) {
                gf_log (this->name, GF_LOG_TRACE,
                        "creating %s on %s", loc->path, subvol->name);
                STACK_WIND (frame, dht_create_cbk,
                            subvol, subvol->fops->create,
                            loc, flags, mode, fd);
        } else {
                /* Choose the minimum filled volume, and create the 
                   files there */
                /* TODO */
                avail_subvol = dht_free_disk_available_subvol (this, subvol);
                if (avail_subvol != subvol) {
                        ret = loc_dup (loc, &local->loc);
                        if (ret == -1) {
                                op_errno = ENOMEM;
                                gf_log (this->name, GF_LOG_ERROR,
                                        "Out of memory");
                                goto err;
                        }

                        local->fd = fd_ref (fd);
                        local->flags = flags;
                        local->mode = mode;

                        local->cached_subvol = avail_subvol;
                        local->hashed_subvol = subvol;
                        gf_log (this->name, GF_LOG_TRACE,
                                "creating %s on %s (link at %s)", loc->path, 
                                avail_subvol->name, subvol->name);
                        dht_linkfile_create (frame, 
                                             dht_create_linkfile_create_cbk,
                                             avail_subvol, subvol, loc);
                } else {
                        gf_log (this->name, GF_LOG_TRACE,
                                "creating %s on %s", loc->path, subvol->name);
                        STACK_WIND (frame, dht_create_cbk,
                                    subvol, subvol->fops->create,
                                    loc, flags, mode, fd);
                        
                }
        }

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL, NULL, NULL);

	return 0;
}


int
dht_mkdir_selfheal_cbk (call_frame_t *frame, void *cookie,
			xlator_t *this,
			int32_t op_ret, int32_t op_errno)
{
	dht_local_t   *local = NULL;
	dht_layout_t  *layout = NULL;


	local = frame->local;
	layout = local->selfheal.layout;

	if (op_ret == 0) {
		inode_ctx_put (local->inode, this, (uint64_t)(long)layout);
		local->selfheal.layout = NULL;
		local->stbuf.st_ino = local->st_ino;
	}

	DHT_STACK_UNWIND (frame, op_ret, op_errno,
			  local->inode, &local->stbuf);

	return 0;
}

int
dht_mkdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
	       int op_ret, int op_errno, inode_t *inode, struct stat *stbuf)
{
	dht_local_t  *local = NULL;
	int           this_call_cnt = 0;
	int           ret = -1;
        int           subvol_filled = 0;
	call_frame_t *prev = NULL;
	dht_layout_t *layout = NULL;
	dht_conf_t   *conf = NULL;

	conf = this->private;
	local = frame->local;
	prev  = cookie;
	layout = local->layout;

        subvol_filled = dht_is_subvol_filled (this, prev->this);

	LOCK (&frame->lock);
	{
                if (subvol_filled && (op_ret != -1)) {
                        ret = dht_layout_merge (this, layout, prev->this,
                                                -1, ENOSPC, NULL);
                } else {
                        ret = dht_layout_merge (this, layout, prev->this,
                                                op_ret, op_errno, NULL);
                }

		if (op_ret == -1) {
			local->op_errno = op_errno;
			goto unlock;
		}
		dht_stat_merge (this, &local->stbuf, stbuf, prev->this);
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = dht_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		local->layout = NULL;
		dht_selfheal_new_directory (frame, dht_mkdir_selfheal_cbk,
					    layout);
	}

        return 0;
}

int
dht_mkdir_hashed_cbk (call_frame_t *frame, void *cookie, 
		      xlator_t *this, int op_ret, int op_errno, 
		      inode_t *inode, struct stat *stbuf)
{
	dht_local_t  *local = NULL;
	int           ret = -1;
	call_frame_t *prev = NULL;
	dht_layout_t *layout = NULL;
	dht_conf_t   *conf = NULL;
	int           i = 0;
	xlator_t     *hashed_subvol = NULL;

	local = frame->local;
	prev  = cookie;
	layout = local->layout;
	conf = this->private;
	hashed_subvol = local->hashed_subvol;

        if (dht_is_subvol_filled (this, hashed_subvol))
                ret = dht_layout_merge (this, layout, prev->this,
                                        -1, ENOSPC, NULL);
        else
                ret = dht_layout_merge (this, layout, prev->this,
                                        op_ret, op_errno, NULL);
        
	if (op_ret == -1) {
		local->op_errno = op_errno;
		goto err;
	}
	local->op_ret = 0;

	dht_stat_merge (this, &local->stbuf, stbuf, prev->this);

	local->st_ino = local->stbuf.st_ino;

	local->call_cnt = conf->subvolume_cnt - 1;
	
	if (local->call_cnt == 0) {
		local->layout = NULL;
		dht_selfheal_directory (frame, dht_mkdir_selfheal_cbk,
					&local->loc, layout);
	}
	for (i = 0; i < conf->subvolume_cnt; i++) {
		if (conf->subvolumes[i] == hashed_subvol)
			continue;
		STACK_WIND (frame, dht_mkdir_cbk,
			    conf->subvolumes[i],
			    conf->subvolumes[i]->fops->mkdir,
			    &local->loc, local->mode);
	}
	return 0;
err:
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL, NULL);
        return 0;
}

int
dht_mkdir (call_frame_t *frame, xlator_t *this,
	   loc_t *loc, mode_t mode)
{
	dht_local_t  *local  = NULL;
	dht_conf_t   *conf = NULL;
        int           op_errno = -1;
	int           ret = -1;
	xlator_t     *hashed_subvol = NULL;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	conf = this->private;

        dht_get_du_info (frame, this, loc);

	local = dht_local_init (frame);
	if (!local) {
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	hashed_subvol = dht_subvol_get_hashed (this, loc);

	if (hashed_subvol == NULL) {
		gf_log (this->name, GF_LOG_DEBUG,
			"hashed subvol not found for %s",
                        loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local->hashed_subvol = hashed_subvol;
	local->inode = inode_ref (loc->inode);
	ret = loc_copy (&local->loc, loc);
	local->mode = mode;

	if (ret == -1) {
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	local->layout = dht_layout_new (this, conf->subvolume_cnt);
	if (!local->layout) {
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	STACK_WIND (frame, dht_mkdir_hashed_cbk,
		    hashed_subvol,
		    hashed_subvol->fops->mkdir,
		    loc, mode);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL, NULL);

	return 0;
}


int
dht_rmdir_selfheal_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
			int op_ret, int op_errno)
{
	dht_local_t  *local = NULL;

	local = frame->local;
	local->layout = NULL;

	DHT_STACK_UNWIND (frame, local->op_ret, local->op_errno);

	return 0;
}


int
dht_rmdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
	       int op_ret, int op_errno)
{
	uint64_t      tmp_layout = 0;
	dht_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;
	dht_layout_t *layout = NULL;

	local = frame->local;
	prev  = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			local->op_ret   = -1;

			if (op_errno != ENOENT)
				local->need_selfheal = 1;

			gf_log (this->name, GF_LOG_DEBUG,
				"rmdir on %s for %s failed (%s)",
				prev->this->name, local->loc.path,
				strerror (op_errno));
			goto unlock;
		}
	}
unlock:
	UNLOCK (&frame->lock);


	this_call_cnt = dht_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		if (local->need_selfheal) {
			inode_ctx_get (local->loc.inode, this, 
				       &tmp_layout);
			layout = (dht_layout_t *)(long)tmp_layout;

			/* TODO: neater interface needed below */
			local->stbuf.st_mode = local->loc.inode->st_mode;

			dht_selfheal_restore (frame, dht_rmdir_selfheal_cbk,
					      &local->loc, layout);
		} else {
			DHT_STACK_UNWIND (frame, local->op_ret,
					  local->op_errno);
		}
	}

        return 0;
}


int
dht_rmdir_do (call_frame_t *frame, xlator_t *this)
{
	dht_local_t  *local = NULL;
	dht_conf_t   *conf = NULL;
	int           i = 0;

	conf = this->private;
	local = frame->local;

	if (local->op_ret == -1)
		goto err;

	local->call_cnt = conf->subvolume_cnt;

	for (i = 0; i < conf->subvolume_cnt; i++) {
		STACK_WIND (frame, dht_rmdir_cbk,
			    conf->subvolumes[i],
			    conf->subvolumes[i]->fops->rmdir,
			    &local->loc);
	}

	return 0;

err:
	DHT_STACK_UNWIND (frame, local->op_ret, local->op_errno);
	return 0;
}


int
dht_rmdir_readdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		       int op_ret, int op_errno, gf_dirent_t *entries)
{
	dht_local_t  *local = NULL;
	int           this_call_cnt = -1;
	call_frame_t *prev = NULL;

	local = frame->local;
	prev  = cookie;

	if (op_ret > 2) {
		gf_log (this->name, GF_LOG_TRACE,
			"readdir on %s for %s returned %d entries",
			prev->this->name, local->loc.path, op_ret);
		local->op_ret = -1;
		local->op_errno = ENOTEMPTY;
	}

	this_call_cnt = dht_frame_return (frame);

	if (is_last_call (this_call_cnt)) {
		dht_rmdir_do (frame, this);
	}

	return 0;
}


int
dht_rmdir_opendir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		       int op_ret, int op_errno, fd_t *fd)
{
	dht_local_t  *local = NULL;
	int           this_call_cnt = -1;
	call_frame_t *prev = NULL;


	local = frame->local;
	prev  = cookie;

	if (op_ret == -1) {
		gf_log (this->name, GF_LOG_DEBUG,
			"opendir on %s for %s failed (%s)",
			prev->this->name, local->loc.path,
			strerror (op_errno));
		goto err;
	}

	STACK_WIND (frame, dht_rmdir_readdir_cbk,
		    prev->this, prev->this->fops->readdir,
		    local->fd, 4096, 0);

	return 0;

err:
	this_call_cnt = dht_frame_return (frame);

	if (is_last_call (this_call_cnt)) {
		dht_rmdir_do (frame, this);
	}

	return 0;
}


int
dht_rmdir (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
	dht_local_t  *local  = NULL;
	dht_conf_t   *conf = NULL;
        int           op_errno = -1;
	int           i = -1;
	int           ret = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	conf = this->private;

	local = dht_local_init (frame);
	if (!local) {
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	local->call_cnt = conf->subvolume_cnt;
	local->op_ret   = 0;

	ret = loc_copy (&local->loc, loc);
	if (ret == -1) {
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	local->fd = fd_create (local->loc.inode, frame->root->pid);
	if (!local->fd) {
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	for (i = 0; i < conf->subvolume_cnt; i++) {
		STACK_WIND (frame, dht_rmdir_opendir_cbk,
			    conf->subvolumes[i],
			    conf->subvolumes[i]->fops->opendir,
			    loc, local->fd);
	}

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno);

	return 0;
}


int
dht_xattrop_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		 int32_t op_ret, int32_t op_errno, dict_t *dict)
{
	DHT_STACK_UNWIND (frame, op_ret, op_errno, dict);
	return 0;
}


int
dht_xattrop (call_frame_t *frame, xlator_t *this, loc_t *loc,
	     gf_xattrop_flags_t flags, dict_t *dict)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;
	dht_local_t  *local = NULL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	subvol = dht_subvol_get_cached (this, loc->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->inode = inode_ref (loc->inode);
	local->call_cnt = 1;

	STACK_WIND (frame,
		    dht_xattrop_cbk,
		    subvol, subvol->fops->xattrop,
		    loc, flags, dict);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_fxattrop_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		  int32_t op_ret, int32_t op_errno, dict_t *dict)
{
	DHT_STACK_UNWIND (frame, op_ret, op_errno, dict);
	return 0;
}


int
dht_fxattrop (call_frame_t *frame, xlator_t *this,
	      fd_t *fd, gf_xattrop_flags_t flags, dict_t *dict)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	subvol = dht_subvol_get_cached (this, fd->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}

	STACK_WIND (frame,
		    dht_fxattrop_cbk,
		    subvol, subvol->fops->fxattrop,
		    fd, flags, dict);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL);

	return 0;
}


int
dht_inodelk_cbk (call_frame_t *frame, void *cookie,
		 xlator_t *this, int32_t op_ret, int32_t op_errno)

{
	DHT_STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}


int32_t
dht_inodelk (call_frame_t *frame, xlator_t *this,
	     const char *volume, loc_t *loc, int32_t cmd, struct flock *lock)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;
	dht_local_t  *local = NULL;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	subvol = dht_subvol_get_cached (this, loc->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->inode = inode_ref (loc->inode);
	local->call_cnt = 1;

	STACK_WIND (frame,
		    dht_inodelk_cbk,
		    subvol, subvol->fops->inodelk,
		    volume, loc, cmd, lock);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno);

	return 0;
}


int
dht_finodelk_cbk (call_frame_t *frame, void *cookie,
		  xlator_t *this, int32_t op_ret, int32_t op_errno)

{
	DHT_STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}


int
dht_finodelk (call_frame_t *frame, xlator_t *this,
	      const char *volume, fd_t *fd, int32_t cmd, struct flock *lock)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	subvol = dht_subvol_get_cached (this, fd->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}


	STACK_WIND (frame,
		    dht_finodelk_cbk,
		    subvol, subvol->fops->finodelk,
		    volume, fd, cmd, lock);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno);

	return 0;
}


int
dht_entrylk_cbk (call_frame_t *frame, void *cookie,
		 xlator_t *this, int32_t op_ret, int32_t op_errno)

{
	DHT_STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}


int
dht_entrylk (call_frame_t *frame, xlator_t *this,
	     const char *volume, loc_t *loc, const char *basename,
	     entrylk_cmd cmd, entrylk_type type)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;
	dht_local_t  *local = NULL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	subvol = dht_subvol_get_cached (this, loc->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->inode = inode_ref (loc->inode);
	local->call_cnt = 1;

	STACK_WIND (frame, dht_entrylk_cbk,
		    subvol, subvol->fops->entrylk,
		    volume, loc, basename, cmd, type);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno);

	return 0;
}


int
dht_fentrylk_cbk (call_frame_t *frame, void *cookie,
		  xlator_t *this, int32_t op_ret, int32_t op_errno)

{
	DHT_STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}


int
dht_fentrylk (call_frame_t *frame, xlator_t *this,
	      const char *volume, fd_t *fd, const char *basename,
	      entrylk_cmd cmd, entrylk_type type)
{
	xlator_t     *subvol = NULL;
        int           op_errno = -1;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	subvol = dht_subvol_get_cached (this, fd->inode);
	if (!subvol) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no cached subvolume for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}

	STACK_WIND (frame, dht_fentrylk_cbk,
		    subvol, subvol->fops->fentrylk,
		    volume, fd, basename, cmd, type);

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno);

	return 0;
}


int
dht_setattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int op_ret, int op_errno, struct stat *statpre,
                 struct stat *statpost)
{
	dht_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;


	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}

		dht_stat_merge (this, &local->stpre, statpre, prev->this);
                dht_stat_merge (this, &local->stpost, statpost, prev->this);
		
		if (local->inode) {
			local->stpre.st_ino = local->inode->ino;
                        local->stpost.st_ino = local->inode->ino;
                }

		local->op_ret = 0;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = dht_frame_return (frame);
	if (is_last_call (this_call_cnt))
		DHT_STACK_UNWIND (frame, local->op_ret, local->op_errno,
				  &local->stpre, &local->stpost);

        return 0;
}


int32_t
dht_setattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
             struct stat *stbuf, int32_t valid)
{
	dht_layout_t *layout = NULL;
	dht_local_t  *local  = NULL;
        int           op_errno = -1;
	int           i = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	layout = dht_layout_get (this, loc->inode);

	if (!layout) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no layout for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	if (!layout_is_sane (layout)) {
		gf_log (this->name, GF_LOG_DEBUG,
			"layout is not sane for path=%s", loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_DEBUG,
			"memory allocation failed :(");
		goto err;
	}

	local->inode = inode_ref (loc->inode);
	local->call_cnt = layout->cnt;

	for (i = 0; i < layout->cnt; i++) {
		STACK_WIND (frame, dht_setattr_cbk,
			    layout->list[i].xlator,
			    layout->list[i].xlator->fops->setattr,
			    loc, stbuf, valid);
	}

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL, NULL);

	return 0;
}


int32_t
dht_fsetattr (call_frame_t *frame, xlator_t *this, fd_t *fd, struct stat *stbuf,
              int32_t valid)
{
	dht_layout_t *layout = NULL;
	dht_local_t  *local  = NULL;
        int           op_errno = -1;
	int           i = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

	layout = dht_layout_get (this, fd->inode);
	if (!layout) {
		gf_log (this->name, GF_LOG_DEBUG,
			"no layout for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}

	if (!layout_is_sane (layout)) {
		gf_log (this->name, GF_LOG_DEBUG,
			"layout is not sane for fd=%p", fd);
		op_errno = EINVAL;
		goto err;
	}

	local = dht_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->inode = inode_ref (fd->inode);
	local->call_cnt = layout->cnt;

	for (i = 0; i < layout->cnt; i++) {
		STACK_WIND (frame, dht_setattr_cbk,
			    layout->list[i].xlator,
			    layout->list[i].xlator->fops->fsetattr,
			    fd, stbuf, valid);
	}

	return 0;

err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	DHT_STACK_UNWIND (frame, -1, op_errno, NULL, NULL);

	return 0;
}


int
dht_forget (xlator_t *this, inode_t *inode)
{
	uint64_t      tmp_layout = 0;
	dht_layout_t *layout = NULL;

	inode_ctx_get (inode, this, &tmp_layout);

	if (!tmp_layout)
		return 0;

	layout = (dht_layout_t *)(long)tmp_layout;
	if (!layout->preset)
		FREE (layout);

	return 0;
}



int
dht_init_subvolumes (xlator_t *this, dht_conf_t *conf)
{
        xlator_list_t *subvols = NULL;
        int            cnt = 0;


        for (subvols = this->children; subvols; subvols = subvols->next)
                cnt++;

        conf->subvolumes = CALLOC (cnt, sizeof (xlator_t *));
        if (!conf->subvolumes) {
                gf_log (this->name, GF_LOG_ERROR,
                        "Out of memory");
                return -1;
        }
        conf->subvolume_cnt = cnt;

        cnt = 0;
        for (subvols = this->children; subvols; subvols = subvols->next)
                conf->subvolumes[cnt++] = subvols->xlator;

	conf->subvolume_status = CALLOC (cnt, sizeof (char));
	if (!conf->subvolume_status) {
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		return -1;
	}

        return 0;
}


int
dht_notify (xlator_t *this, int event, void *data, ...)
{
	xlator_t   *subvol = NULL;
	int         cnt    = -1;
	int         i      = -1;
	dht_conf_t *conf   = NULL;
	int         ret    = -1;


	conf = this->private;

	switch (event) {
	case GF_EVENT_CHILD_UP:
		subvol = data;

		conf->gen++;

		for (i = 0; i < conf->subvolume_cnt; i++) {
			if (subvol == conf->subvolumes[i]) {
				cnt = i;
				break;
			}
		}

		if (cnt == -1) {
			gf_log (this->name, GF_LOG_DEBUG,
				"got GF_EVENT_CHILD_UP bad subvolume %s",
				subvol->name);
			break;
		}

		LOCK (&conf->subvolume_lock);
		{
			conf->subvolume_status[cnt] = 1;
		}
		UNLOCK (&conf->subvolume_lock);

                /* one of the node came back up, do a stat update */
                dht_get_du_info_for_subvol (this, cnt);

		break;

	case GF_EVENT_CHILD_DOWN:
		subvol = data;

		for (i = 0; i < conf->subvolume_cnt; i++) {
			if (subvol == conf->subvolumes[i]) {
				cnt = i;
				break;
			}
		}

		if (cnt == -1) {
			gf_log (this->name, GF_LOG_DEBUG,
				"got GF_EVENT_CHILD_DOWN bad subvolume %s",
				subvol->name);
			break;
		}

		LOCK (&conf->subvolume_lock);
		{
			conf->subvolume_status[cnt] = 0;
		}
		UNLOCK (&conf->subvolume_lock);

		break;
	}

	ret = default_notify (this, event, data);

	return ret;
}

