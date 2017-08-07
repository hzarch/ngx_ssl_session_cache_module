#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#ifndef _NGX_SSL_SESSION_CACHE_MODULE_H_
#define _NGX_SSL_SESSION_CACHE_MODULE_H_

#define NGX_RSSC_MODULE  0x52535343  /* "RSSC" */

#define NGX_SSL_SESSION_CACHE_MSG_TYPE_SET           1
#define NGX_SSL_SESSION_CACHE_MSG_TYPE_GET           2
#define NGX_SSL_SESSION_CACHE_MSG_TYPE_DEL           3
#define NGX_SSL_SESSION_CACHE_MSG_TYPE_AUTH          4
#define NGX_SSL_SESSION_CACHE_MSG_TYPE_CHECK         5

#define NGX_SSL_SESSION_CACHE_PARSE_MSG_OK           0
#define NGX_SSL_SESSION_CACHE_PARSE_MSG_MORE_DATA   -1 
#define NGX_SSL_SESSION_CACHE_PARSE_MSG_PROTO_ERR   -2 
#define NGX_SSL_SESSION_CACHE_PARSE_MSG_TYPE_ERR    -3 
#define NGX_SSL_SESSION_CACHE_PARSE_MSG_DATA_LARGE  -4 
#define NGX_SSL_SESSION_CACHE_PARSE_MSG_STATUS_ERR  -5 

#define NGX_SSL_SESSION_CACHE_OFF   0
#define NGX_SSL_SESSION_CACHE_ON    1

struct ngx_ssl_session_cache_ctx_s;
typedef struct ngx_ssl_session_cache_ctx_s ngx_ssl_session_cache_ctx_t;

typedef struct {
    ngx_int_t             msg_type;
    ngx_connection_t     *c;
    ngx_buf_t            *out;
    ngx_uint_t            seq;
    ngx_queue_t           queue;
    ngx_str_t             session;
} ngx_ssl_session_cache_node_t;

typedef struct {
    ngx_buf_t      *(*auth)(ngx_ssl_session_cache_ctx_t *ctx, const u_char *auth, int len);

    ngx_buf_t      *(*set)(ngx_ssl_session_cache_ctx_t *ctx, const u_char *key,int keylen,
                       const u_char *session, int sesslen, unsigned int timeout);

    ngx_buf_t      *(*get)(ngx_ssl_session_cache_ctx_t *ctx, const u_char *key, int len);
    ngx_buf_t      *(*delete)(ngx_ssl_session_cache_ctx_t *ctx, const u_char *key, int len);
    ngx_buf_t      *(*check)(ngx_ssl_session_cache_ctx_t *ctx);
    ngx_int_t       (*parse)(ngx_buf_t *in, ngx_ssl_session_cache_node_t *node);
} ngx_ssl_session_cache_method_t;

typedef struct {
    ngx_url_t                        url;
    ngx_int_t                        queue_depth;
    ngx_msec_t                       proc_timeout;
    ngx_msec_t                       interval;
    ngx_msec_t                       session_timeout;
    ngx_int_t                        onoff;
    ngx_str_t                        auth;
    ngx_ssl_session_cache_ctx_t     *cache_ctx;
    ngx_ssl_session_cache_method_t  *cache_method;
} ngx_ssl_session_cache_conf_t;



struct ngx_ssl_session_cache_ctx_s {
    ngx_pool_t                      *pool;
    ngx_event_t                      ev;
    ngx_buf_t                        in;
    ngx_buf_t                       *free_out_buf;                     
    ngx_ssl_session_cache_node_t    *free_node; 
    ngx_log_t                       *log;
    ngx_queue_t                      write_queue;
    ngx_queue_t                      read_queue;
    ngx_peer_connection_t            pc;
    ngx_ssl_session_cache_conf_t    *conf;
    ngx_int_t                        is_connected;
    ngx_int_t                        queue_num;
};


typedef struct {
    ngx_str_t                       name;
    ngx_ssl_session_cache_method_t *(*init)(ngx_pool_t *pool, ngx_uint_t *default_port);
}ngx_ssl_session_cache_module_t;

ngx_uint_t
ngx_ssl_session_cache_get_size_len(ngx_uint_t size);

ngx_buf_t *
ngx_ssl_session_cache_get_buf(ngx_ssl_session_cache_ctx_t *cache_ctx, size_t size);

ngx_int_t
ngx_ssl_session_cache_add_timers(ngx_cycle_t *cycle, ngx_ssl_session_cache_conf_t *sscf);

int
ngx_ssl_session_cache_new_session(ngx_ssl_session_cache_ctx_t *cache_ctx,
    ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess);

ngx_ssl_session_t *
ngx_ssl_session_cache_get_session(ngx_ssl_session_cache_ctx_t *cache_ctx,
    ngx_ssl_conn_t *ssl_conn, const u_char *id, int len, int *copy);

void
ngx_ssl_session_cache_remove_session(ngx_ssl_session_cache_ctx_t *cache_ctx,
                                ngx_ssl_session_t *sess);

char*
ngx_ssl_session_cache_conf(ngx_ssl_session_cache_conf_t *sccf,
                      ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#endif
