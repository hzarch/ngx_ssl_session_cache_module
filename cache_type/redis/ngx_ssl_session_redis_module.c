#include <ngx_config.h>
#include <ngx_core.h>

#include "../../ngx_ssl_session_cache_module.h"


static ngx_ssl_session_cache_method_t *
ngx_ssl_session_redis_int_module(ngx_pool_t *pool, ngx_uint_t *default_port);

static ngx_ssl_session_cache_module_t ngx_ssl_session_redis_module_ctx = {
    ngx_string("redis"),
    ngx_ssl_session_redis_int_module
};

ngx_module_t  ngx_ssl_session_redis_module = {
    NGX_MODULE_V1,
    &ngx_ssl_session_redis_module_ctx,          /* module context */
    NULL,                                       /* module directives */
    NGX_RSSC_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_buf_t *
ngx_ssl_session_redis_auth(ngx_ssl_session_cache_ctx_t *cache_ctx, const u_char *auth, int len)
{
    ngx_buf_t                   *msg;
    ngx_str_t                    redis_string;
    ngx_uint_t                   redis_string_len;

    ngx_str_set(&redis_string, "*2\r\n"
                               "$4\r\n"
                               "AUTH\r\n"
                               "$%d\r\n"
                               "%s\r\n");

    redis_string_len = redis_string.len + NGX_INT32_LEN - 2 + len - 2;

    msg = ngx_ssl_session_cache_get_buf(cache_ctx, redis_string_len);
    if (msg == NULL) {
        return NULL;
    }

    msg->last = ngx_snprintf(msg->last, redis_string_len, (char*)redis_string.data, len, auth);

    return msg;
}

static ngx_buf_t *
ngx_ssl_session_redis_set(ngx_ssl_session_cache_ctx_t *cache_ctx, const u_char *key,int keylen,
    const u_char *session, int sesslen, unsigned int timeout)
{
    ngx_buf_t                      *msg;
    ngx_str_t                       redis_string;
    ngx_uint_t                      redis_string_len;


    ngx_str_set(&redis_string, "*5\r\n"
                               "$3\r\n"
                               "SET\r\n"
                               "$%d\r\n"
                               "%s\r\n"
                               "$%d\r\n"
                               "%s\r\n"
                               "$2\r\n"
                               "EX\r\n"
                               "$%d\r\n"
                               "%ud\r\n");


    redis_string_len = redis_string.len + ngx_ssl_session_cache_get_size_len(keylen) - 2 + keylen - 2 + \
                       ngx_ssl_session_cache_get_size_len(sesslen) - 2 + sesslen - 2 + \
                       ngx_ssl_session_cache_get_size_len(timeout)*2  - 5;

    msg = ngx_ssl_session_cache_get_buf(cache_ctx, redis_string_len);
    if (msg == NULL) {
        return NULL;
    }

    msg->last[0] = '*'; msg->last[1] = '5'; msg->last[2] = '\r'; msg->last[3] = '\n';
    msg->last[4] = '$'; msg->last[5] = '3'; msg->last[6] = '\r'; msg->last[7] = '\n';
    msg->last[8] = 'S'; msg->last[9] = 'E'; msg->last[10] = 'T'; msg->last[11] = '\r'; msg->last[12] = '\n';

    msg->last += 13;

    msg->last = ngx_snprintf(msg->last, msg->end - msg->last, "$%d", keylen);
    *msg->last++ = '\r';
    *msg->last++ = '\n';

    msg->last = ngx_cpymem(msg->last, key, keylen);
    *msg->last++ = '\r';
    *msg->last++ = '\n';

    
    msg->last = ngx_snprintf(msg->last, msg->end - msg->last, "$%d", sesslen);
    *msg->last++ = '\r';
    *msg->last++ = '\n';

    msg->last = ngx_cpymem(msg->last, session, sesslen);

    msg->last[0] = '\r'; msg->last[1] = '\n';

    msg->last[2] = '$'; msg->last[3] = '2'; msg->last[4] = '\r'; msg->last[5] = '\n';
    msg->last[6] = 'E'; msg->last[7] = 'X'; msg->last[8] = '\r'; msg->last[9] = '\n';

    msg->last += 10;

    msg->last = ngx_snprintf(msg->last, msg->end - msg->last, "$%d\r\n%ud\r\n", ngx_ssl_session_cache_get_size_len(timeout), timeout); 

    return msg;
}

static ngx_buf_t *
ngx_ssl_session_redis_get(ngx_ssl_session_cache_ctx_t *cache_ctx, const u_char *key, int len)
{
    ngx_buf_t                      *msg;
    ngx_str_t                       redis_string;
    ngx_uint_t                      redis_string_len;

    ngx_str_set(&redis_string, "*2\r\n"
                               "$3\r\n"
                               "GET\r\n"
                               "$%d\r\n"
                               "%s\r\n");

    redis_string_len = redis_string.len + NGX_INT32_LEN - 2 + len - 2;

    msg = ngx_ssl_session_cache_get_buf(cache_ctx, redis_string_len);
    if (msg == NULL) {
        return NULL;
    }

    ngx_str_set(&redis_string, "*2\r\n"
                               "$3\r\n"
                               "GET\r\n"
                               "$%d\r\n");

    msg->last = ngx_snprintf(msg->last, msg->end - msg->last, (char*)redis_string.data, len);

    msg->last = ngx_cpymem(msg->last, key, len);
    *msg->last++ = '\r';
    *msg->last++ = '\n';

    return msg;
}

static ngx_buf_t *
ngx_ssl_session_redis_delete(ngx_ssl_session_cache_ctx_t *cache_ctx, const u_char *key, int len)
{
    ngx_buf_t                      *msg;
    ngx_str_t                       redis_string;
    ngx_uint_t                      redis_string_len;

    ngx_str_set(&redis_string, "*2\r\n"
                               "$3\r\n"
                               "DEL\r\n"
                               "$%d\r\n"
                               "%s\r\n");

    redis_string_len = redis_string.len + NGX_INT32_LEN - 2 + len - 2;

    msg = ngx_ssl_session_cache_get_buf(cache_ctx, redis_string_len);
    if (msg == NULL) {
        return NULL;
    }

    ngx_str_set(&redis_string, "*2\r\n"
                               "$3\r\n"
                               "DEL\r\n"
                               "$%d\r\n");

    msg->last = ngx_snprintf(msg->last, msg->end - msg->last, (char*)redis_string.data, len);

    msg->last = ngx_cpymem(msg->last, key, len);
    *msg->last++ = '\r';
    *msg->last++ = '\n';

    return msg;

}

static ngx_buf_t *
ngx_ssl_session_redis_check(ngx_ssl_session_cache_ctx_t *cache_ctx)
{
    ngx_buf_t                      *msg;
    ngx_str_t                       redis_string;
    ngx_uint_t                      redis_string_len;

    ngx_str_set(&redis_string, "*1\r\n"
                               "$4\r\n"
                               "PING\r\n");

    redis_string_len = redis_string.len;

    msg = ngx_ssl_session_cache_get_buf(cache_ctx, redis_string_len);
    if (msg == NULL) {
        return NULL;
    }

    msg->last = ngx_cpymem(msg->last, redis_string.data, redis_string.len);

    return msg;
}

static ngx_int_t
ngx_ssl_session_redis_parse(ngx_buf_t *in, ngx_ssl_session_cache_node_t *node)
{
    u_char      *pos;
    u_char      *str_cr;
    ngx_int_t    len;

    str_cr = ngx_strlchr(in->pos, in->last, '\r');
    if (str_cr == NULL || str_cr + 1 == in->last) {
        return NGX_SSL_SESSION_CACHE_PARSE_MSG_MORE_DATA; 
    }

    pos = in->pos;

    switch (*pos) {

    case '+':

        if (str_cr - pos == 3 && pos[1] == 'O' && pos[2] == 'K' &&
              (node->msg_type == NGX_SSL_SESSION_CACHE_MSG_TYPE_SET ||
               node->msg_type == NGX_SSL_SESSION_CACHE_MSG_TYPE_AUTH)) {
            in->pos += 5; 
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_OK;
        }


        if (str_cr - pos == 5 &&
             pos[1] == 'P' && pos[2] == 'O' && pos[3] == 'N' && pos[4] == 'G' &&
             node->msg_type == NGX_SSL_SESSION_CACHE_MSG_TYPE_CHECK) {
            in->pos += 7; 
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_OK;
        }

        return NGX_SSL_SESSION_CACHE_PARSE_MSG_TYPE_ERR;

    case '-':

        *str_cr = '\0';
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "ssl session redis response msg[%s]", pos + 1 );
        return NGX_SSL_SESSION_CACHE_PARSE_MSG_STATUS_ERR;

    case '$':

        pos++;

        if (node->msg_type != NGX_SSL_SESSION_CACHE_MSG_TYPE_GET) {
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_TYPE_ERR; 
        }

        if (pos[0] == '-' && pos[1] == '1') {
            node->session.data = NULL;

            in->pos += 5;
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_OK;
        }

        len = ngx_atoi(pos, str_cr - pos);
        if (len == NGX_ERROR) {
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_PROTO_ERR; 
        }

        if (in->last - str_cr - 4 < len) {
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_MORE_DATA; 
        }

        node->session.data = str_cr + 2;
        node->session.len  = len;

        in->pos = str_cr  + 2 + len + 2; 

        return NGX_SSL_SESSION_CACHE_PARSE_MSG_OK;

    case ':':

        if (node->msg_type != NGX_SSL_SESSION_CACHE_MSG_TYPE_DEL) {
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_TYPE_ERR; 
        }

        in->pos = str_cr + 2;

        return NGX_SSL_SESSION_CACHE_PARSE_MSG_OK;

    default:
        return NGX_SSL_SESSION_CACHE_PARSE_MSG_PROTO_ERR;
    }
}

static ngx_ssl_session_cache_method_t *
ngx_ssl_session_redis_int_module(ngx_pool_t *pool, ngx_uint_t *default_port)
{
    ngx_ssl_session_cache_method_t   *method;

    method = ngx_pcalloc(pool, sizeof(*method));
    if (method == NULL) {
        return NULL;
    }

    method->auth   = ngx_ssl_session_redis_auth;
    method->set    = ngx_ssl_session_redis_set;
    method->get    = ngx_ssl_session_redis_get;
    method->delete = ngx_ssl_session_redis_delete;
    method->check  = ngx_ssl_session_redis_check;
    method->parse  = ngx_ssl_session_redis_parse;

    *default_port = 6379;

    return method;
}
