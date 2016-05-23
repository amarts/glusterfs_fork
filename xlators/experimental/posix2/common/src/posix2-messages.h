/*Copyright (c) 2016 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#ifndef _POSIX2_COMMON_MESSAGES_H_
#define _POSIX2_COMMON_MESSAGES_H_

#include "glfs-message-id.h"

/*! \file posix2-common-messages.h
 *  \brief PPOSIX2 log-message IDs and their descriptions
 *
 */

/* NOTE: Rules for message additions
 * 1) Each instance of a message is _better_ left with a unique message ID, even
 *    if the message format is the same. Reasoning is that, if the message
 *    format needs to change in one instance, the other instances are not
 *    impacted or the new change does not change the ID of the instance being
 *    modified.
 * 2) Addition of a message,
 *       - Should increment the GLFS_NUM_MESSAGES
 *       - Append to the list of messages defined, towards the end
 *       - Retain macro naming as glfs_msg_X (for redability across developers)
 * NOTE: Rules for message format modifications
 * 3) Check acorss the code if the message ID macro in question is reused
 *    anywhere. If reused then then the modifications should ensure correctness
 *    everywhere, or needs a new message ID as (1) above was not adhered to. If
 *    not used anywhere, proceed with the required modification.
 * NOTE: Rules for message deletion
 * 4) Check (3) and if used anywhere else, then cannot be deleted. If not used
 *    anywhere, then can be deleted, but will leave a hole by design, as
 *    addition rules specify modification to the end of the list and not filling
 *    holes.
 */

#define GLFS_POSIX2_BASE          GLFS_MSGID_COMP_POSIX2
#define GLFS_POSIX2_NUM_MESSAGES  1
#define GLFS_POSIX2_MSGID_END     (GLFS_POSIX2_BASE + GLFS_POSIX2_NUM_MESSAGES \
                                  + 1)

/* Messages with message IDs */
#define glfs_msg_start_x GLFS_POSIX2_BASE, "Invalid: Start of messages"

/* TODO: Message ID start is still unknown, so all @messageid need correction */
/*!
 * @messageid   1
 * @diagnosis   None
 * @recommendedaction  None
 *
 */
#define POSIX2_MSG_VOLUME_CONF_ERROR        (GLFS_POSIX2_BASE + 1)

#define glfs_msg_end_x GLFS_POSIX2_MSGID_END, "Invalid: End of messages"

#endif /* _POSIX2_COMMON_MESSAGES_H_ */
