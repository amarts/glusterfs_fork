#!/usr/bin/python

import os
import sys

curdir = os.path.dirname(sys.argv[0])
gendir = os.path.join(curdir, '../../../../../libglusterfs/src')
sys.path.append(gendir)
from generator import ops, fop_subs, cbk_subs, generate

COMMON_OPS_FOP_TEMPLATE = """
int32_t
rio_server_ds_@NAME@ (call_frame_t *frame, xlator_t *this,
                      @LONG_ARGS@)
{
        xlator_t *subvol;
        struct rio_conf *conf;

        VALIDATE_OR_GOTO (frame, bailout);
        VALIDATE_OR_GOTO (this, error);
        conf = this->private;
        VALIDATE_OR_GOTO (conf, error);

        subvol = conf->riocnf_server_local_xlator;

        STACK_WIND (frame, rio_server_ds_@NAME@_cbk, subvol,
                    subvol->fops->@NAME@,
                    @SHORT_ARGS@);
        return 0;
error:
        STACK_UNWIND (@NAME@, frame, -1, errno,
                      @CBK_ERROR_ARGS@);
bailout:
        return 0;
}
"""

POST_IATT_OP_CBK_TEMPLATE = """
int32_t
rio_server_ds_@NAME@_cbk (call_frame_t *frame, void *cookie,
                       xlator_t *this, int32_t op_ret, int32_t op_errno,
                       @LONG_ARGS@)
{
        VALIDATE_OR_GOTO (frame, bailout);

        if (op_ret != 0) {
                goto done;
        }

        rio_iatt_cleanse_ds (buf);
done:
        STACK_UNWIND (@NAME@, frame, op_ret, op_errno,
                      @SHORT_ARGS@);
bailout:
        return 0;
}
"""

PRE_POST_IATT_OP_CBK_TEMPLATE = """
int32_t
rio_server_ds_@NAME@_cbk (call_frame_t *frame, void *cookie,
                       xlator_t *this, int32_t op_ret, int32_t op_errno,
                       @LONG_ARGS@)
{
        VALIDATE_OR_GOTO (frame, bailout);

        if (op_ret != 0) {
                goto done;
        }

        rio_iatt_cleanse_ds (prebuf);
        rio_iatt_cleanse_ds (postbuf);
done:
        STACK_UNWIND (@NAME@, frame, op_ret, op_errno,
                      @SHORT_ARGS@);
bailout:
        return 0;
}
"""

post_iatt_fops = ['readv']
pre_post_iatt_fops = ['writev', 'truncate', 'ftruncate', 'fallocate',
                      'discard', 'zerofill']


def gen_defaults():
    for name in ops:
        if name in post_iatt_fops:
            print generate(POST_IATT_OP_CBK_TEMPLATE, name, cbk_subs)
            print generate(COMMON_OPS_FOP_TEMPLATE, name, fop_subs)
        elif name in pre_post_iatt_fops:
            print generate(PRE_POST_IATT_OP_CBK_TEMPLATE, name, cbk_subs)
            print generate(COMMON_OPS_FOP_TEMPLATE, name, fop_subs)


for l in open(sys.argv[1], 'r').readlines():
    if l.find('#pragma generate') != -1:
        print "/* BEGIN GENERATED CODE - DO NOT MODIFY */"
        gen_defaults()
        print "/* END GENERATED CODE */"
    else:
        print l[:-1]
