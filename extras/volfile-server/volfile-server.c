/*
   Copyright (c) 2021 Kadalu.IO <https://kadalu.io>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <netdb.h>
#include <signal.h>
#include <libgen.h>
#include <dlfcn.h>

#include <sys/utsname.h>

#include <stdint.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <semaphore.h>
#include <errno.h>
#include <pwd.h>

#ifdef GF_LINUX_HOST_OS
#ifdef HAVE_LINUX_OOM_H
#include <linux/oom.h>
#else
#define OOM_SCORE_ADJ_MIN (-1000)
#define OOM_SCORE_ADJ_MAX 1000
#define OOM_DISABLE (-17)
#define OOM_ADJUST_MAX 15
#endif
#endif

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#include <glusterfs/xlator.h>
#include <glusterfs/glusterfs.h>
#include <glusterfs/compat.h>
#include <glusterfs/logging.h>
#include "glusterfsd-messages.h"
#include <glusterfs/dict.h>
#include <glusterfs/list.h>
#include <glusterfs/timer.h>
#include "volfile-server.h"
#include <glusterfs/revision.h>
#include <glusterfs/common-utils.h>
#include <glusterfs/gf-event.h>
#include <glusterfs/statedump.h>
#include <glusterfs/latency.h>
#include "glusterfsd-mem-types.h"
#include <glusterfs/syscall.h>
#include <glusterfs/call-stub.h>
#include <fnmatch.h>
#include "rpc-clnt.h"
#include <glusterfs/syncop.h>
#include <glusterfs/client_t.h>
#include <glusterfs/monitoring.h>

#include <glusterfs/daemon.h>

/* using argp for command line parsing */
static char gf_doc[] = "";
static char argp_doc[] =
    "--volfile-server=SERVER [MOUNT-POINT]\n"
    "--volfile=VOLFILE [MOUNT-POINT]";
const char *argp_program_version =
    "" PACKAGE_NAME " " PACKAGE_VERSION
    "\nRepository revision: " GLUSTERFS_REPOSITORY_REVISION
    "\n"
    "Copyright (c) 2006-2016 Red Hat, Inc. "
    "<https://www.gluster.org/>\n"
    "GlusterFS comes with ABSOLUTELY NO WARRANTY.\n"
    "It is licensed to you under your choice of the GNU Lesser\n"
    "General Public License, version 3 or any later version (LGPLv3\n"
    "or later), or the GNU General Public License, version 2 (GPLv2),\n"
    "in all cases as published by the Free Software Foundation.";
const char *argp_program_bug_address = "<" PACKAGE_BUGREPORT ">";

static error_t
parse_opts(int32_t key, char *arg, struct argp_state *_state);

static struct argp_option gf_options[] = {
    {0, 0, 0, 0, "Basic options:"},
    {"volfile-directory", ARGP_VOLFILE_DIR_KEY, "DIR", 0,
     "Server to get the volume file from. Unix domain socket path when "
     "transport type 'unix'. This option overrides --volfile option"},

    {"log-level", ARGP_LOG_LEVEL_KEY, "LOGLEVEL", 0,
     "Logging severity.  Valid options are DEBUG, INFO, WARNING, ERROR, "
     "CRITICAL, TRACE and NONE [default: INFO]"},
    {"log-file", ARGP_LOG_FILE_KEY, "LOGFILE", 0,
     "File to use for logging [default: " DEFAULT_LOG_FILE_DIRECTORY
     "/" PACKAGE_NAME ".log"
     "]"},
    {"logger", ARGP_LOGGER, "LOGGER", 0,
     "Set which logging sub-system to "
     "log to, valid options are: gluster-log and syslog, "
     "[default: \"gluster-log\"]"},
    {"log-format", ARGP_LOG_FORMAT, "LOG-FORMAT", 0,
     "Set log format, valid"
     " options are: no-msg-id and with-msg-id, [default: \"with-msg-id\"]"},
    {"log-buf-size", ARGP_LOG_BUF_SIZE, "LOG-BUF-SIZE", 0,
     "Set logging "
     "buffer size, [default: 5]"},
    {"log-flush-timeout", ARGP_LOG_FLUSH_TIMEOUT, "LOG-FLUSH-TIMEOUT", 0,
     "Set log flush timeout, [default: 2 minutes]"},

    {"pid-file", ARGP_PID_FILE_KEY, "PIDFILE", 0, "File to use as pid file"},
    {"no-daemon", ARGP_NO_DAEMON_KEY, 0, 0, "Run in foreground"},
    {"debug", ARGP_DEBUG_KEY, 0, 0,
     "Run in debug mode.  This option sets --no-daemon, --log-level "
     "to DEBUG and --log-file to console"},
    {"print-logdir", ARGP_PRINT_LOGDIR_KEY, 0, OPTION_ARG_OPTIONAL,
     "Print path of default log directory"},

    {"localtime-logging", ARGP_LOCALTIME_LOGGING_KEY, 0, 0,
     "Enable localtime logging"},
    {
        0,
    }};

static struct argp argp = {gf_options, parse_opts, argp_doc, gf_doc};

int
glusterfs_pidfile_cleanup(glusterfs_ctx_t *ctx);
int
glusterfs_volumes_init(glusterfs_ctx_t *ctx);
int
glusterfs_mgmt_init(glusterfs_ctx_t *ctx);
int
glusterfs_listener_init(glusterfs_ctx_t *ctx);

#define DICT_SET_VAL(method, dict, key, val, msgid)                            \
    if (method(dict, key, val)) {                                              \
        gf_smsg("glusterfsd", GF_LOG_ERROR, 0, msgid, "key=%s", key);          \
        goto err;                                                              \
    }


static FILE *
get_volfp(glusterfs_ctx_t *ctx)
{
    cmd_args_t *cmd_args = NULL;
    FILE *specfp = NULL;

    cmd_args = &ctx->cmd_args;

    if ((specfp = fopen(cmd_args->volfile, "r")) == NULL) {
        gf_smsg("glusterfsd", GF_LOG_ERROR, errno, glusterfsd_msg_9,
                "volume_file=%s", cmd_args->volfile, NULL);
        return NULL;
    }

    gf_msg_debug("glusterfsd", 0, "loading volume file %s", cmd_args->volfile);

    return specfp;
}

static char *volfile_dir;

static error_t
parse_opts(int key, char *arg, struct argp_state *state)
{
    cmd_args_t *cmd_args = NULL;
    uint32_t n = 0;
#ifdef GF_LINUX_HOST_OS
    int32_t k = 0;
    struct oom_api_info *api = NULL;
#endif
    double d = 0.0;
    gf_boolean_t b = _gf_false;
    char *tmp_str = NULL;
    char *port_str = NULL;
    struct passwd *pw = NULL;
    int ret = 0;

    cmd_args = state->input;

    switch (key) {
        case ARGP_VOLFILE_DIR_KEY:
            volfile_dir = gf_strdup(arg);

            break;

        case ARGP_PRINT_LOGDIR_KEY:
            cmd_args->print_logdir = _gf_true;
            break;

        case ARGP_LOG_LEVEL_KEY:
            if (strcasecmp(arg, ARGP_LOG_LEVEL_NONE_OPTION) == 0) {
                cmd_args->log_level = GF_LOG_NONE;
                break;
            }
            if (strcasecmp(arg, ARGP_LOG_LEVEL_CRITICAL_OPTION) == 0) {
                cmd_args->log_level = GF_LOG_CRITICAL;
                break;
            }
            if (strcasecmp(arg, ARGP_LOG_LEVEL_ERROR_OPTION) == 0) {
                cmd_args->log_level = GF_LOG_ERROR;
                break;
            }
            if (strcasecmp(arg, ARGP_LOG_LEVEL_WARNING_OPTION) == 0) {
                cmd_args->log_level = GF_LOG_WARNING;
                break;
            }
            if (strcasecmp(arg, ARGP_LOG_LEVEL_INFO_OPTION) == 0) {
                cmd_args->log_level = GF_LOG_INFO;
                break;
            }
            if (strcasecmp(arg, ARGP_LOG_LEVEL_DEBUG_OPTION) == 0) {
                cmd_args->log_level = GF_LOG_DEBUG;
                break;
            }
            if (strcasecmp(arg, ARGP_LOG_LEVEL_TRACE_OPTION) == 0) {
                cmd_args->log_level = GF_LOG_TRACE;
                break;
            }

            argp_failure(state, -1, 0, "unknown log level %s", arg);
            break;

        case ARGP_LOG_FILE_KEY:
            cmd_args->log_file = gf_strdup(arg);
            break;

        case ARGP_PID_FILE_KEY:
            cmd_args->pid_file = gf_strdup(arg);
            break;

        case ARGP_NO_DAEMON_KEY:
            cmd_args->no_daemon_mode = ENABLE_NO_DAEMON_MODE;
            break;

        case ARGP_DEBUG_KEY:
            cmd_args->debug_mode = ENABLE_DEBUG_MODE;
            break;
        case ARGP_KEY_NO_ARGS:
            break;

        case ARGP_LOGGER:
            if (strcasecmp(arg, GF_LOGGER_GLUSTER_LOG) == 0)
                cmd_args->logger = gf_logger_glusterlog;
            else if (strcasecmp(arg, GF_LOGGER_SYSLOG) == 0)
                cmd_args->logger = gf_logger_syslog;
            else
                argp_failure(state, -1, 0, "unknown logger %s", arg);

            break;

        case ARGP_LOG_FORMAT:
            if (strcasecmp(arg, GF_LOG_FORMAT_NO_MSG_ID) == 0)
                cmd_args->log_format = gf_logformat_traditional;
            else if (strcasecmp(arg, GF_LOG_FORMAT_WITH_MSG_ID) == 0)
                cmd_args->log_format = gf_logformat_withmsgid;
            else
                argp_failure(state, -1, 0, "unknown log format %s", arg);

            break;

        case ARGP_LOG_BUF_SIZE:
            if (gf_string2uint32(arg, &cmd_args->log_buf_size)) {
                argp_failure(state, -1, 0, "unknown log buf size option %s",
                             arg);
            } else if (cmd_args->log_buf_size > GF_LOG_LRU_BUFSIZE_MAX) {
                argp_failure(state, -1, 0,
                             "Invalid log buf size %s. "
                             "Valid range: [" GF_LOG_LRU_BUFSIZE_MIN_STR
                             "," GF_LOG_LRU_BUFSIZE_MAX_STR "]",
                             arg);
            }

            break;

        case ARGP_LOG_FLUSH_TIMEOUT:
            if (gf_string2uint32(arg, &cmd_args->log_flush_timeout)) {
                argp_failure(state, -1, 0,
                             "unknown log flush timeout option %s", arg);
            } else if ((cmd_args->log_flush_timeout <
                        GF_LOG_FLUSH_TIMEOUT_MIN) ||
                       (cmd_args->log_flush_timeout >
                        GF_LOG_FLUSH_TIMEOUT_MAX)) {
                argp_failure(state, -1, 0,
                             "Invalid log flush timeout %s. "
                             "Valid range: [" GF_LOG_FLUSH_TIMEOUT_MIN_STR
                             "," GF_LOG_FLUSH_TIMEOUT_MAX_STR "]",
                             arg);
            }

            break;

        case ARGP_LOCALTIME_LOGGING_KEY:
            cmd_args->localtime_logging = 1;
            break;
    }
    return 0;
}
void
cleanup_and_exit(int signum)
{
    glusterfs_ctx_t *ctx = NULL;
    xlator_t *trav = NULL;
    xlator_t *top;
    xlator_t *victim;
    xlator_list_t **trav_p;

    ctx = glusterfsd_ctx;

    if (!ctx)
        return;

    /* To take or not to take the mutex here and in the other
     * signal handler - gf_print_trace() - is the big question here.
     *
     * Taking mutex in signal handler would mean that if the process
     * receives a fatal signal while another thread is holding
     * ctx->log.log_buf_lock to perhaps log a message in _gf_msg_internal(),
     * the offending thread hangs on the mutex lock forever without letting
     * the process exit.
     *
     * On the other hand. not taking the mutex in signal handler would cause
     * it to modify the lru_list of buffered log messages in a racy manner,
     * corrupt the list and potentially give rise to an unending
     * cascade of SIGSEGVs and other re-entrancy issues.
     */

    gf_log_disable_suppression_before_exit(ctx);

    gf_msg_callingfn("", GF_LOG_WARNING, 0, glusterfsd_msg_32,
                     "received signum (%d), shutting down", signum);

    if (ctx->cleanup_started)
        return;
    pthread_mutex_lock(&ctx->cleanup_lock);
    {
        ctx->cleanup_started = 1;

        /* signout should be sent to all the bricks in case brick mux is enabled
         * and multiple brick instances are attached to this process
         */
        if (ctx->active) {
            top = ctx->active->first;
            for (trav_p = &top->children; *trav_p; trav_p = &(*trav_p)->next) {
                victim = (*trav_p)->xlator;
                rpc_clnt_mgmt_pmap_signout(ctx, victim->name);
            }
        } else {
            rpc_clnt_mgmt_pmap_signout(ctx, NULL);
        }

        /* below part is a racy code where the rpcsvc object is freed.
         * But in another thread (epoll thread), upon poll error in the
         * socket the transports are cleaned up where again rpcsvc object
         * is accessed (which is already freed by the below function).
         * Since the process is about to be killed don't execute the function
         * below.
         */
        /* if (ctx->listener) { */
        /*         (void) glusterfs_listener_stop (ctx); */
        /* } */

        /* Call fini() of FUSE xlator first:
         * so there are no more requests coming and
         * 'umount' of mount point is done properly */
        trav = ctx->root;
        if (trav && trav->fini) {
            THIS = trav;
            trav->fini(trav);
        }

        glusterfs_pidfile_cleanup(ctx);

#if 0
        /* TODO: Properly do cleanup_and_exit(), with synchronization */
        if (ctx->mgmt) {
                /* cleanup the saved-frames before last unref */
                rpc_clnt_connection_cleanup (&ctx->mgmt->conn);
                rpc_clnt_unref (ctx->mgmt);
        }
#endif

        trav = NULL;

        /* previously we were releasing the cleanup mutex lock before the
           process exit. As we are releasing the cleanup mutex lock, before
           the process can exit some other thread which is blocked on
           cleanup mutex lock is acquiring the cleanup mutex lock and
           trying to acquire some resources which are already freed as a
           part of cleanup. To avoid this, we are exiting the process without
           releasing the cleanup mutex lock. This will not cause any lock
           related issues as the process which acquired the lock is going down
         */
        /* NOTE: Only the least significant 8 bits i.e (signum & 255)
           will be available to parent process on calling exit() */
        exit(abs(signum));
    }
}

static void
reincarnate(int signum)
{
    int ret = 0;
    glusterfs_ctx_t *ctx = NULL;
    cmd_args_t *cmd_args = NULL;

    ctx = glusterfsd_ctx;
    cmd_args = &ctx->cmd_args;

    gf_msg_trace("gluster", 0, "received reincarnate request (sig:HUP)");

    /* Also, SIGHUP should do logrotate */
    gf_log_logrotate(1);

    if (ret < 0)
        gf_smsg("glusterfsd", GF_LOG_ERROR, 0, glusterfsd_msg_12, NULL);

    return;
}

void
emancipate(glusterfs_ctx_t *ctx, int ret)
{
    /* break free from the parent */
    if (ctx->daemon_pipe[1] != -1) {
        sys_write(ctx->daemon_pipe[1], (void *)&ret, sizeof(ret));
        sys_close(ctx->daemon_pipe[1]);
        ctx->daemon_pipe[1] = -1;
    }
}

static int
glusterfs_ctx_defaults_init(glusterfs_ctx_t *ctx)
{
    cmd_args_t *cmd_args = NULL;
    struct rlimit lim = {
        0,
    };
    int ret = -1;

    if (!ctx)
        return ret;

    ret = xlator_mem_acct_init(THIS, gfd_mt_end);
    if (ret != 0) {
        gf_smsg(THIS->name, GF_LOG_CRITICAL, 0, glusterfsd_msg_34, NULL);
        return ret;
    }

    /* reset ret to -1 so that we don't need to explicitly
     * set it in all error paths before "goto err"
     */
    ret = -1;

    /* monitoring should be enabled by default */
    ctx->measure_latency = true;

    ctx->process_uuid = generate_glusterfs_ctx_id();
    if (!ctx->process_uuid) {
        gf_smsg("", GF_LOG_CRITICAL, 0, glusterfsd_msg_13, NULL);
        goto out;
    }

    ctx->page_size = 128 * GF_UNIT_KB;

    ctx->iobuf_pool = iobuf_pool_new();
    if (!ctx->iobuf_pool) {
        gf_smsg("", GF_LOG_CRITICAL, 0, glusterfsd_msg_14, "iobuf", NULL);
        goto out;
    }

    ctx->event_pool = gf_event_pool_new(DEFAULT_EVENT_POOL_SIZE,
                                        STARTING_EVENT_THREADS);
    if (!ctx->event_pool) {
        gf_smsg("", GF_LOG_CRITICAL, 0, glusterfsd_msg_14, "event", NULL);
        goto out;
    }

    ctx->pool = GF_CALLOC(1, sizeof(call_pool_t), gfd_mt_call_pool_t);
    if (!ctx->pool) {
        gf_smsg("", GF_LOG_CRITICAL, 0, glusterfsd_msg_14, "call", NULL);
        goto out;
    }

    INIT_LIST_HEAD(&ctx->pool->all_frames);
    LOCK_INIT(&ctx->pool->lock);

    /* frame_mem_pool size 112 * 4k */
    ctx->pool->frame_mem_pool = mem_pool_new(call_frame_t, 4096);
    if (!ctx->pool->frame_mem_pool) {
        gf_smsg("", GF_LOG_CRITICAL, 0, glusterfsd_msg_14, "frame", NULL);
        goto out;
    }
    /* stack_mem_pool size 256 * 1024 */
    ctx->pool->stack_mem_pool = mem_pool_new(call_stack_t, 1024);
    if (!ctx->pool->stack_mem_pool) {
        gf_smsg("", GF_LOG_CRITICAL, 0, glusterfsd_msg_14, "stack", NULL);
        goto out;
    }

    ctx->stub_mem_pool = mem_pool_new(call_stub_t, 1024);
    if (!ctx->stub_mem_pool) {
        gf_smsg("", GF_LOG_CRITICAL, 0, glusterfsd_msg_14, "stub", NULL);
        goto out;
    }

    ctx->dict_pool = mem_pool_new(dict_t, GF_MEMPOOL_COUNT_OF_DICT_T);
    if (!ctx->dict_pool)
        goto out;

    ctx->dict_pair_pool = mem_pool_new(data_pair_t,
                                       GF_MEMPOOL_COUNT_OF_DATA_PAIR_T);
    if (!ctx->dict_pair_pool)
        goto out;

    ctx->dict_data_pool = mem_pool_new(data_t, GF_MEMPOOL_COUNT_OF_DATA_T);
    if (!ctx->dict_data_pool)
        goto out;

    ctx->logbuf_pool = mem_pool_new(log_buf_t, GF_MEMPOOL_COUNT_OF_LRU_BUF_T);
    if (!ctx->logbuf_pool)
        goto out;

    pthread_mutex_init(&ctx->notify_lock, NULL);
    pthread_mutex_init(&ctx->cleanup_lock, NULL);
    pthread_cond_init(&ctx->notify_cond, NULL);

    ctx->clienttable = gf_clienttable_alloc();
    if (!ctx->clienttable)
        goto out;

    cmd_args = &ctx->cmd_args;

    /* parsing command line arguments */
    cmd_args->log_level = DEFAULT_LOG_LEVEL;
    cmd_args->logger = gf_logger_glusterlog;
    cmd_args->log_format = gf_logformat_withmsgid;
    cmd_args->log_buf_size = GF_LOG_LRU_BUFSIZE_DEFAULT;
    cmd_args->log_flush_timeout = GF_LOG_FLUSH_TIMEOUT_DEFAULT;

    cmd_args->mac_compat = GF_OPTION_DISABLE;
#ifdef GF_DARWIN_HOST_OS
    /* On Darwin machines, O_APPEND is not handled,
     * which may corrupt the data
     */
    cmd_args->fuse_direct_io_mode = GF_OPTION_DISABLE;
#else
    cmd_args->fuse_direct_io_mode = GF_OPTION_DEFERRED;
#endif
    cmd_args->fuse_attribute_timeout = -1;
    cmd_args->fuse_entry_timeout = -1;
    cmd_args->fopen_keep_cache = GF_OPTION_DEFERRED;
    cmd_args->kernel_writeback_cache = GF_OPTION_DEFERRED;
    cmd_args->fuse_flush_handle_interrupt = GF_OPTION_DEFERRED;

    if (ctx->mem_acct_enable)
        cmd_args->mem_acct = 1;

    INIT_LIST_HEAD(&cmd_args->xlator_options);
    INIT_LIST_HEAD(&cmd_args->volfile_servers);
    ctx->pxl_count = 0;
    ctx->diskxl_count = 0;
    pthread_mutex_init(&ctx->fd_lock, NULL);
    pthread_cond_init(&ctx->fd_cond, NULL);
    INIT_LIST_HEAD(&ctx->janitor_fds);
    pthread_mutex_init(&ctx->xl_lock, NULL);
    pthread_cond_init(&ctx->xl_cond, NULL);
    INIT_LIST_HEAD(&ctx->diskth_xl);

    lim.rlim_cur = RLIM_INFINITY;
    lim.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &lim);

    ret = 0;
out:

    if (ret) {
        if (ctx->pool) {
            mem_pool_destroy(ctx->pool->frame_mem_pool);
            mem_pool_destroy(ctx->pool->stack_mem_pool);
        }
        GF_FREE(ctx->pool);
        mem_pool_destroy(ctx->stub_mem_pool);
        mem_pool_destroy(ctx->dict_pool);
        mem_pool_destroy(ctx->dict_data_pool);
        mem_pool_destroy(ctx->dict_pair_pool);
        mem_pool_destroy(ctx->logbuf_pool);
    }

    return ret;
}

static int
logging_init(glusterfs_ctx_t *ctx, const char *progpath)
{
    cmd_args_t *cmd_args = NULL;
    int ret = 0;

    cmd_args = &ctx->cmd_args;

    if (cmd_args->log_file == NULL) {
        ret = gf_set_log_file_path(cmd_args, ctx);
        if (ret == -1) {
            fprintf(stderr,
                    "ERROR: failed to set the log file "
                    "path\n");
            return -1;
        }
    }

    if (cmd_args->log_ident == NULL) {
        ret = gf_set_log_ident(cmd_args);
        if (ret == -1) {
            fprintf(stderr,
                    "ERROR: failed to set the log "
                    "identity\n");
            return -1;
        }
    }

    /* finish log set parameters before init */
    gf_log_set_loglevel(ctx, cmd_args->log_level);

    gf_log_set_localtime(cmd_args->localtime_logging);

    gf_log_set_logger(cmd_args->logger);

    gf_log_set_logformat(cmd_args->log_format);

    gf_log_set_log_buf_size(cmd_args->log_buf_size);

    gf_log_set_log_flush_timeout(cmd_args->log_flush_timeout);

    if (gf_log_init(ctx, cmd_args->log_file, cmd_args->log_ident) == -1) {
        fprintf(stderr, "ERROR: failed to open logfile %s\n",
                cmd_args->log_file);
        return -1;
    }

    /* At this point, all the logging related parameters are initialised
     * except for the log flush timer, which will be injected post fork(2)
     * in daemonize() . During this time, any log message that is logged
     * will be kept buffered. And if the list that holds these messages
     * overflows, then the same lru policy is used to drive out the least
     * recently used message and displace it with the message just logged.
     */

    return 0;
}

void
gf_check_and_set_mem_acct(int argc, char *argv[])
{
    int i = 0;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--no-mem-accounting") == 0) {
            gf_global_mem_acct_enable_set(0);
            break;
        }
    }
}

int
parse_cmdline(int argc, char *argv[], glusterfs_ctx_t *ctx)
{
    int process_mode = 0;
    int ret = 0;
    struct stat stbuf = {
        0,
    };
    char timestr[GF_TIMESTR_SIZE];
    char tmp_logfile[1024] = {0};
    char *tmp_logfile_dyn = NULL;
    char *tmp_logfilebase = NULL;
    cmd_args_t *cmd_args = NULL;
    int len = 0;
    char *thin_volfileid = NULL;

    cmd_args = &ctx->cmd_args;

    /* Need to set lru_limit to below 0 to indicate there was nothing
       specified. This is needed as 0 is a valid option, and may not be
       default value. */
    cmd_args->lru_limit = -1;

    argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, cmd_args);

    if (cmd_args->print_logdir) {
        /* Just print, nothing else to do */
        goto out;
    }

    if (ENABLE_DEBUG_MODE == cmd_args->debug_mode) {
        cmd_args->log_level = GF_LOG_DEBUG;
        cmd_args->log_file = gf_strdup("/dev/stderr");
        cmd_args->no_daemon_mode = ENABLE_NO_DAEMON_MODE;
    }


    ret = 0;
out:
    return ret;
}

int
glusterfs_pidfile_setup(glusterfs_ctx_t *ctx)
{
    cmd_args_t *cmd_args = NULL;
    int ret = -1;
    FILE *pidfp = NULL;

    cmd_args = &ctx->cmd_args;

    if (!cmd_args->pid_file)
        return 0;

    pidfp = fopen(cmd_args->pid_file, "a+");
    if (!pidfp) {
        gf_smsg("glusterfsd", GF_LOG_ERROR, errno, glusterfsd_msg_17,
                "pidfile=%s", cmd_args->pid_file, NULL);
        goto out;
    }

    ctx->pidfp = pidfp;

    ret = 0;
out:

    return ret;
}

int
glusterfs_pidfile_cleanup(glusterfs_ctx_t *ctx)
{
    cmd_args_t *cmd_args = NULL;

    cmd_args = &ctx->cmd_args;

    if (!ctx->pidfp)
        return 0;

    gf_msg_trace("glusterfsd", 0, "pidfile %s cleanup", cmd_args->pid_file);

    if (ctx->cmd_args.pid_file) {
        GF_FREE(ctx->cmd_args.pid_file);
        ctx->cmd_args.pid_file = NULL;
    }

    lockf(fileno(ctx->pidfp), F_ULOCK, 0);
    fclose(ctx->pidfp);
    ctx->pidfp = NULL;

    return 0;
}

int
glusterfs_pidfile_update(glusterfs_ctx_t *ctx, pid_t pid)
{
    cmd_args_t *cmd_args = NULL;
    int ret = 0;
    FILE *pidfp = NULL;

    cmd_args = &ctx->cmd_args;

    pidfp = ctx->pidfp;
    if (!pidfp)
        return 0;

    ret = lockf(fileno(pidfp), F_TLOCK, 0);
    if (ret) {
        gf_smsg("glusterfsd", GF_LOG_ERROR, errno, glusterfsd_msg_18,
                "pidfile=%s", cmd_args->pid_file, NULL);
        return ret;
    }

    ret = sys_ftruncate(fileno(pidfp), 0);
    if (ret) {
        gf_smsg("glusterfsd", GF_LOG_ERROR, errno, glusterfsd_msg_20,
                "pidfile=%s", cmd_args->pid_file, NULL);
        return ret;
    }

    ret = fprintf(pidfp, "%d\n", pid);
    if (ret <= 0) {
        gf_smsg("glusterfsd", GF_LOG_ERROR, errno, glusterfsd_msg_21,
                "pidfile=%s", cmd_args->pid_file, NULL);
        return ret;
    }

    ret = fflush(pidfp);
    if (ret) {
        gf_smsg("glusterfsd", GF_LOG_ERROR, errno, glusterfsd_msg_21,
                "pidfile=%s", cmd_args->pid_file, NULL);
        return ret;
    }

    gf_msg_debug("glusterfsd", 0, "pidfile %s updated with pid %d",
                 cmd_args->pid_file, pid);

    return 0;
}

void *
glusterfs_sigwaiter(void *arg)
{
    sigset_t set;
    int ret = 0;
    int sig = 0;
    char *file = NULL;

    sigemptyset(&set);
    sigaddset(&set, SIGINT);  /* cleanup_and_exit */
    sigaddset(&set, SIGTERM); /* cleanup_and_exit */
    sigaddset(&set, SIGHUP);  /* reincarnate */
    sigaddset(&set, SIGUSR1); /* gf_proc_dump_info */
    sigaddset(&set, SIGUSR2);

    for (;;) {
        ret = sigwait(&set, &sig);
        if (ret)
            continue;

        switch (sig) {
            case SIGINT:
            case SIGTERM:
                cleanup_and_exit(sig);
                break;
            case SIGHUP:
                reincarnate(sig);
                break;
            default:

                break;
        }
    }

    return NULL;
}

void
glusterfsd_print_trace(int signum)
{
    gf_print_trace(signum, glusterfsd_ctx);
}

int
glusterfs_signals_setup(glusterfs_ctx_t *ctx)
{
    sigset_t set;
    int ret = 0;

    sigemptyset(&set);

    /* common setting for all threads */
    signal(SIGSEGV, glusterfsd_print_trace);
    signal(SIGABRT, glusterfsd_print_trace);
    signal(SIGILL, glusterfsd_print_trace);
    signal(SIGTRAP, glusterfsd_print_trace);
    signal(SIGFPE, glusterfsd_print_trace);
    signal(SIGBUS, glusterfsd_print_trace);
    signal(SIGINT, cleanup_and_exit);
    signal(SIGPIPE, SIG_IGN);

    /* block these signals from non-sigwaiter threads */
    sigaddset(&set, SIGTERM); /* cleanup_and_exit */
    sigaddset(&set, SIGHUP);  /* reincarnate */
    sigaddset(&set, SIGUSR1); /* gf_proc_dump_info */
    sigaddset(&set, SIGUSR2);

    /* Signals needed for asynchronous framework. */
    sigaddset(&set, GF_ASYNC_SIGQUEUE);
    sigaddset(&set, GF_ASYNC_SIGCTRL);

    ret = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (ret) {
        gf_smsg("glusterfsd", GF_LOG_WARNING, errno, glusterfsd_msg_22, NULL);
        return ret;
    }

    ret = gf_thread_create(&ctx->sigwaiter, NULL, glusterfs_sigwaiter,
                           (void *)&set, "sigwait");
    if (ret) {
        /*
          TODO:
          fallback to signals getting handled by other threads.
          setup the signal handlers
        */
        gf_smsg("glusterfsd", GF_LOG_WARNING, errno, glusterfsd_msg_23, NULL);
        return ret;
    }

    return ret;
}

int
daemonize(glusterfs_ctx_t *ctx)
{
    int ret = -1;
    cmd_args_t *cmd_args = NULL;
    int cstatus = 0;
    int err = 1;
    int child_pid = 0;

    cmd_args = &ctx->cmd_args;

    ret = glusterfs_pidfile_setup(ctx);
    if (ret)
        goto out;

    if (cmd_args->no_daemon_mode) {
        goto postfork;
    }

    if (cmd_args->debug_mode)
        goto postfork;

    ret = pipe(ctx->daemon_pipe);
    if (ret) {
        /* If pipe() fails, retain daemon_pipe[] = {-1, -1}
           and parent will just not wait for child status
        */
        ctx->daemon_pipe[0] = -1;
        ctx->daemon_pipe[1] = -1;
    }

    ret = os_daemon_return(0, 0);
    switch (ret) {
        case -1:
            if (ctx->daemon_pipe[0] != -1) {
                sys_close(ctx->daemon_pipe[0]);
                sys_close(ctx->daemon_pipe[1]);
            }

            gf_smsg("daemonize", GF_LOG_ERROR, errno, glusterfsd_msg_24, NULL);
            goto out;
        case 0:
            /* child */
            /* close read */
            sys_close(ctx->daemon_pipe[0]);
            break;
        default:
            /* parent */
            /* close write */
            child_pid = ret;
            sys_close(ctx->daemon_pipe[1]);

            if (ctx->mnt_pid > 0) {
                ret = waitpid(ctx->mnt_pid, &cstatus, 0);
                if (!(ret == ctx->mnt_pid)) {
                    if (WIFEXITED(cstatus)) {
                        err = WEXITSTATUS(cstatus);
                    } else {
                        err = cstatus;
                    }
                    gf_smsg("daemonize", GF_LOG_ERROR, 0, glusterfsd_msg_25,
                            NULL);
                    exit(err);
                }
            }
            sys_read(ctx->daemon_pipe[0], (void *)&err, sizeof(err));
            /* NOTE: Only the least significant 8 bits i.e (err & 255)
               will be available to parent process on calling exit() */
            if (err)
                _exit(abs(err));

            _exit(0);
    }

postfork:
    gf_log("glusterfs", GF_LOG_INFO, "Pid of current running process is %d",
           getpid());
    ret = gf_log_inject_timer_event(ctx);

    glusterfs_signals_setup(ctx);
out:
    return ret;
}

int
glusterfs_process_volfp(glusterfs_ctx_t *ctx, FILE *fp)
{
    glusterfs_graph_t *graph = NULL;
    int ret = -1;
    xlator_t *trav = NULL;

    if (!ctx)
        return -1;

    graph = glusterfs_graph_construct(fp);
    if (!graph) {
        gf_smsg("", GF_LOG_ERROR, 0, glusterfsd_msg_26, NULL);
        goto out;
    }

    for (trav = graph->first; trav; trav = trav->next) {
        if (strcmp(trav->type, "mount/fuse") == 0) {
            gf_smsg("glusterfsd", GF_LOG_ERROR, 0, glusterfsd_msg_27, NULL);
            goto out;
        }
    }

    xlator_t *xl = graph->first;
    if (xl && (strcmp(xl->type, "protocol/server") == 0)) {
        (void)copy_opts_to_child(xl, FIRST_CHILD(xl), "*auth*");
    }

    ret = glusterfs_graph_prepare(graph, ctx, ctx->cmd_args.volume_name);
    if (ret) {
        goto out;
    }

    ret = glusterfs_graph_activate(graph, ctx);

    if (ret) {
        goto out;
    }

    gf_log_dump_graph(fp, graph);

    ret = 0;
out:
    if (fp)
        fclose(fp);

    if (ret) {
        /* TODO This code makes to generic for all graphs
           client as well as servers.For now it destroys
           graph only for server-side xlators not for client-side
           xlators, before destroying a graph call xlator fini for
           xlators those call xlator_init to avoid leak
        */
        if (graph) {
            xl = graph->first;
            if ((ctx->active != graph) &&
                (xl && !strcmp(xl->type, "protocol/server"))) {
                /* Take dict ref for every graph xlator to avoid dict leak
                   at the time of graph destroying
                */
                glusterfs_graph_fini(graph);
                glusterfs_graph_destroy(graph);
            }
        }

        /* there is some error in setting up the first graph itself */
        if (!ctx->active) {
            emancipate(ctx, ret);
            cleanup_and_exit(ret);
        }
    }

    return ret;
}

int
glusterfs_volumes_init(glusterfs_ctx_t *ctx)
{
    FILE *fp = NULL;
    cmd_args_t *cmd_args = NULL;
    int ret = 0;

    cmd_args = &ctx->cmd_args;

    if (cmd_args->sock_file) {
        ret = glusterfs_listener_init(ctx);
        if (ret)
            goto out;
    }

    if (cmd_args->volfile_server) {
        ret = glusterfs_mgmt_init(ctx);
        /* return, do not emancipate() yet */
        return ret;
    }

    fp = get_volfp(ctx);

    if (!fp) {
        gf_smsg("glusterfsd", GF_LOG_ERROR, 0, glusterfsd_msg_28, NULL);
        ret = -1;
        goto out;
    }

    ret = glusterfs_process_volfp(ctx, fp);
    if (ret)
        goto out;

out:
    emancipate(ctx, ret);
    return ret;
}

/* This is the only legal global pointer  */
glusterfs_ctx_t *glusterfsd_ctx;

int
main(int argc, char *argv[])
{
    glusterfs_ctx_t *ctx = NULL;
    int ret = -1;
    char cmdlinestr[PATH_MAX] = {
        0,
    };
    cmd_args_t *cmd = NULL;

    gf_check_and_set_mem_acct(argc, argv);

    ctx = glusterfs_ctx_new();
    if (!ctx) {
        gf_smsg("glusterfs", GF_LOG_CRITICAL, 0, glusterfsd_msg_29, NULL);
        return ENOMEM;
    }
    glusterfsd_ctx = ctx;

    ret = glusterfs_globals_init(ctx);
    if (ret)
        return ret;

    THIS->ctx = ctx;

    ret = glusterfs_ctx_defaults_init(ctx);
    if (ret)
        goto out;

    ret = parse_cmdline(argc, argv, ctx);
    if (ret)
        goto out;
    cmd = &ctx->cmd_args;

    if (cmd->print_logdir) {
        printf("%s\n", DEFAULT_LOG_FILE_DIRECTORY);
        goto out;
    }
    ret = logging_init(ctx, argv[0]);
    if (ret)
        goto out;

    /* log the version of glusterfs running here along with the actual
       command line options. */
    {
        int i = 0;
        int pos = 0;
        int len = snprintf(cmdlinestr, sizeof(cmdlinestr), "%s", argv[0]);
        for (i = 1; (i < argc) && (len > 0); i++) {
            pos += len;
            len = snprintf(cmdlinestr + pos, sizeof(cmdlinestr) - pos, " %s",
                           argv[i]);
            if ((len <= 0) || (len >= (sizeof(cmdlinestr) - pos))) {
                gf_smsg("glusterfs", GF_LOG_ERROR, 0, glusterfsd_msg_029, NULL);
                ret = -1;
                goto out;
            }
        }
        gf_smsg(argv[0], GF_LOG_INFO, 0, glusterfsd_msg_30, "arg=%s", argv[0],
                "version=%s", PACKAGE_VERSION, "cmdlinestr=%s", cmdlinestr,
                NULL);

        ctx->cmdlinestr = gf_strdup(cmdlinestr);
    }

    ret = daemonize(ctx);
    if (ret)
        goto out;

    /*
     * If we do this before daemonize, the pool-sweeper thread dies with
     * the parent, but we want to do it as soon as possible after that in
     * case something else depends on pool allocations.
     */
    mem_pools_init();

    ret = gf_async_init(ctx);
    if (ret < 0) {
        goto out;
    }

    ctx->env = syncenv_new(0, 0, 0);
    if (!ctx->env) {
        gf_smsg("", GF_LOG_ERROR, 0, glusterfsd_msg_31, NULL);
        goto out;
    }

    /* do this _after_ daemonize() */
    if (!glusterfs_ctx_tw_get(ctx)) {
        ret = -1;
        goto out;
    }

    ret = glusterfs_volumes_init(ctx);
    if (ret)
        goto out;

    ret = gf_event_dispatch(ctx->event_pool);

out:
    //    glusterfs_ctx_destroy (ctx);
    gf_async_fini();
    return ret;
}
