/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "gluster1.h"

bool_t
xdr_gf1_cluster_type (XDR *xdrs, gf1_cluster_type *objp)
{

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_replace_op (XDR *xdrs, gf1_cli_replace_op *objp)
{

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_enum_friends_list (XDR *xdrs, gf1_cli_enum_friends_list *objp)
{

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_probe_req (XDR *xdrs, gf1_cli_probe_req *objp)
{

	 if (!xdr_string (xdrs, &objp->hostname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_probe_rsp (XDR *xdrs, gf1_cli_probe_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->hostname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_deprobe_req (XDR *xdrs, gf1_cli_deprobe_req *objp)
{

	 if (!xdr_string (xdrs, &objp->hostname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_deprobe_rsp (XDR *xdrs, gf1_cli_deprobe_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->hostname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_peer_list_req (XDR *xdrs, gf1_cli_peer_list_req *objp)
{

	 if (!xdr_int (xdrs, &objp->flags))
		 return FALSE;
	 if (!xdr_bytes (xdrs, (char **)&objp->dict.dict_val, (u_int *) &objp->dict.dict_len, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_peer_list_rsp (XDR *xdrs, gf1_cli_peer_list_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_bytes (xdrs, (char **)&objp->friends.friends_val, (u_int *) &objp->friends.friends_len, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_create_vol_req (XDR *xdrs, gf1_cli_create_vol_req *objp)
{

	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	 if (!xdr_gf1_cluster_type (xdrs, &objp->type))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->count))
		 return FALSE;
	 if (!xdr_bytes (xdrs, (char **)&objp->bricks.bricks_val, (u_int *) &objp->bricks.bricks_len, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_create_vol_rsp (XDR *xdrs, gf1_cli_create_vol_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_delete_vol_req (XDR *xdrs, gf1_cli_delete_vol_req *objp)
{

	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_delete_vol_rsp (XDR *xdrs, gf1_cli_delete_vol_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_start_vol_req (XDR *xdrs, gf1_cli_start_vol_req *objp)
{

	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_start_vol_rsp (XDR *xdrs, gf1_cli_start_vol_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_stop_vol_req (XDR *xdrs, gf1_cli_stop_vol_req *objp)
{

	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_stop_vol_rsp (XDR *xdrs, gf1_cli_stop_vol_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_rename_vol_req (XDR *xdrs, gf1_cli_rename_vol_req *objp)
{

	 if (!xdr_string (xdrs, &objp->old_volname, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->new_volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_rename_vol_rsp (XDR *xdrs, gf1_cli_rename_vol_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_defrag_vol_req (XDR *xdrs, gf1_cli_defrag_vol_req *objp)
{

	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_defrag_vol_rsp (XDR *xdrs, gf1_cli_defrag_vol_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_add_brick_req (XDR *xdrs, gf1_cli_add_brick_req *objp)
{

	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	 if (!xdr_gf1_cluster_type (xdrs, &objp->type))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->count))
		 return FALSE;
	 if (!xdr_bytes (xdrs, (char **)&objp->bricks.bricks_val, (u_int *) &objp->bricks.bricks_len, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_add_brick_rsp (XDR *xdrs, gf1_cli_add_brick_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_remove_brick_req (XDR *xdrs, gf1_cli_remove_brick_req *objp)
{

	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	 if (!xdr_gf1_cluster_type (xdrs, &objp->type))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->count))
		 return FALSE;
	 if (!xdr_bytes (xdrs, (char **)&objp->bricks.bricks_val, (u_int *) &objp->bricks.bricks_len, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_remove_brick_rsp (XDR *xdrs, gf1_cli_remove_brick_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_replace_brick_req (XDR *xdrs, gf1_cli_replace_brick_req *objp)
{

	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	 if (!xdr_gf1_cli_replace_op (xdrs, &objp->op))
		 return FALSE;
	 if (!xdr_bytes (xdrs, (char **)&objp->src_brick.src_brick_val, (u_int *) &objp->src_brick.src_brick_len, ~0))
		 return FALSE;
	 if (!xdr_bytes (xdrs, (char **)&objp->dst_brick.dst_brick_val, (u_int *) &objp->dst_brick.dst_brick_len, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_replace_brick_rsp (XDR *xdrs, gf1_cli_replace_brick_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_set_vol_req (XDR *xdrs, gf1_cli_set_vol_req *objp)
{

	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	 if (!xdr_bytes (xdrs, (char **)&objp->dict.dict_val, (u_int *) &objp->dict.dict_len, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gf1_cli_set_vol_rsp (XDR *xdrs, gf1_cli_set_vol_rsp *objp)
{

	 if (!xdr_int (xdrs, &objp->op_ret))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->op_errno))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->volname, ~0))
		 return FALSE;
	return TRUE;
}
