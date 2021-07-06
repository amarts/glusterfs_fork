/*
   Copyright (c) 2021 Kadalu.IO <https://kadalu.io>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef __VOLFILE_SERVER_H__
#define __VOLFILE_SERVER_H__

#include "rpcsvc.h"
#include "glusterd1-xdr.h"

#define DEFAULT_EVENT_POOL_SIZE 16384

#define ARGP_LOG_LEVEL_NONE_OPTION "NONE"
#define ARGP_LOG_LEVEL_TRACE_OPTION "TRACE"
#define ARGP_LOG_LEVEL_CRITICAL_OPTION "CRITICAL"
#define ARGP_LOG_LEVEL_ERROR_OPTION "ERROR"
#define ARGP_LOG_LEVEL_WARNING_OPTION "WARNING"
#define ARGP_LOG_LEVEL_INFO_OPTION "INFO"
#define ARGP_LOG_LEVEL_DEBUG_OPTION "DEBUG"

#define ENABLE_NO_DAEMON_MODE 1
#define ENABLE_DEBUG_MODE 1

#define GF_MEMPOOL_COUNT_OF_DICT_T 4096
/* Considering 4 key/value pairs in a dictionary on an average */
#define GF_MEMPOOL_COUNT_OF_DATA_T (GF_MEMPOOL_COUNT_OF_DICT_T * 4)
#define GF_MEMPOOL_COUNT_OF_DATA_PAIR_T (GF_MEMPOOL_COUNT_OF_DICT_T * 4)

#define GF_MEMPOOL_COUNT_OF_LRU_BUF_T 256

enum argp_option_keys {
    ARGP_VOLFILE_DIR_KEY = 's',
    ARGP_LOG_LEVEL_KEY = 'L',
    ARGP_LOG_FILE_KEY = 'l',
    ARGP_PID_FILE_KEY = 'p',
    ARGP_NO_DAEMON_KEY = 'N',
    ARGP_DEBUG_KEY = 133,
    ARGP_LOG_SERVER_KEY = 146,
    ARGP_LOG_SERVER_PORT_KEY = 147,
    ARGP_LOGGER = 168,
    ARGP_LOG_FORMAT = 169,
    ARGP_LOG_BUF_SIZE = 170,
    ARGP_LOG_FLUSH_TIMEOUT = 171,
    ARGP_LOCALTIME_LOGGING_KEY = 177,
    ARGP_PRINT_LOGDIR_KEY = 185,
};


extern glusterfs_ctx_t *glusterfsd_ctx;
#endif /* __GLUSTERFSD_H__ */
