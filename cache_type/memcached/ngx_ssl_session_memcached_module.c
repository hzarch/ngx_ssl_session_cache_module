#include <ngx_config.h>
#include <ngx_core.h>

#include "../../ngx_ssl_session_cache_module.h"


#if (NGX_HAVE_PACK_PRAGMA)
#pragma pack(push, 1)
#elif (NGX_SOLARIS)
#pragma pack(1)
#else
#error "ngx_ssl_session_memcached_module needs structure packing pragma support"
#endif

typedef struct {
    u_char                magic;
    u_char                opcode;
    uint16_t              key_length;
    u_char                extras_length;
    u_char                data_type;
    union {
        uint16_t            vbucket_id;
        uint16_t            status;
    }v;
    uint32_t              body_length;
    uint32_t              opaque;
    uint64_t              cas;
} ngx_memcached_msg_head_t;

typedef struct {
    uint32_t       flags;
    uint32_t       expiration;
} ngx_memcached_msg_set_extras_t;

#if (NGX_HAVE_PACK_PRAGMA)
#pragma pack(pop)
#elif (NGX_SOLARIS)
#pragma pack()
#else
#error "ngx_ssl_session_memcached_module needs structure packing pragma support"
#endif


#define MEMCACHED_OPCODE_GET  0x00
#define MEMCACHED_OPCODE_SET  0x01
#define MEMCACHED_OPCODE_DEL  0x04
#define MEMCACHED_OPCODE_CHK  0x0a
#define MEMCACHED_OPCODE_ATH  0x21

static ngx_ssl_session_cache_method_t *
ngx_ssl_session_cache_int_module(ngx_pool_t *pool, ngx_uint_t *default_port);

static ngx_ssl_session_cache_module_t ngx_ssl_session_memcached_module_ctx = {
    ngx_string("memcached"),
    ngx_ssl_session_cache_int_module
};

ngx_module_t  ngx_ssl_session_memcached_module = {
    NGX_MODULE_V1,
    &ngx_ssl_session_memcached_module_ctx,      /* module context */
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
ngx_ssl_session_memcached_auth(ngx_ssl_session_cache_ctx_t *cache_ctx, const u_char *auth, int len)
{
    ngx_buf_t                   *msg;
    ngx_memcached_msg_head_t    *head;
    ngx_str_t                    key;

    ngx_str_set(&key, "PLAIN");

    msg = ngx_ssl_session_cache_get_buf(cache_ctx,
             sizeof(ngx_memcached_msg_head_t) + len + key.len);
    if (msg == NULL) {
        return NULL; 
    }

    head = (ngx_memcached_msg_head_t*)msg->start;

    ngx_memzero(head, sizeof(*head));

    head->magic            = 0x80;
    head->opcode           = MEMCACHED_OPCODE_ATH;
    head->key_length       = htons((uint16_t)key.len);
    head->body_length      = htonl(len+key.len);


    msg->last = ngx_cpymem(msg->pos + sizeof(*head), key.data, key.len);
    msg->last = ngx_cpymem(msg->last, auth, len);

    return msg;
}

static ngx_buf_t *
ngx_ssl_session_memcached_set(ngx_ssl_session_cache_ctx_t *cache_ctx, const u_char *key,int keylen,
    const u_char *session, int sesslen, unsigned int timeout)
{
    ngx_buf_t                      *msg;
    ngx_memcached_msg_head_t        *head;
    ngx_memcached_msg_set_extras_t  *extras;

    msg = ngx_ssl_session_cache_get_buf(cache_ctx,
             sizeof(ngx_memcached_msg_head_t) + keylen + sesslen + 8);
    if (msg == NULL) {
        return NULL; 
    }

    head = (ngx_memcached_msg_head_t*)msg->start;

    ngx_memzero(head, sizeof(*head));

    head->magic            = 0x80;
    head->opcode           = MEMCACHED_OPCODE_SET;
    head->key_length       = htons((uint16_t)keylen);
    head->extras_length    = 0x08;
    head->body_length      = htonl(keylen + sesslen + 8);


    extras = (ngx_memcached_msg_set_extras_t*) (msg->start + sizeof(*head));

    extras->flags      = 0x00;
    extras->expiration = htonl(timeout);

    msg->last = ngx_cpymem(msg->pos + sizeof(*head) + sizeof(*extras), key, keylen);

    msg->last = ngx_cpymem(msg->last, session, sesslen);

    return msg;
}

static ngx_buf_t *
ngx_ssl_session_memcached_get(ngx_ssl_session_cache_ctx_t *cache_ctx, const u_char *key, int len)
{
    ngx_buf_t                   *msg;
    ngx_memcached_msg_head_t     *head;

    msg = ngx_ssl_session_cache_get_buf(cache_ctx,
             sizeof(ngx_memcached_msg_head_t) + len);
    if (msg == NULL) {
        return NULL; 
    }

    head = (ngx_memcached_msg_head_t*)msg->start;

    ngx_memzero(head, sizeof(*head));

    head->magic            = 0x80;
    head->opcode           = MEMCACHED_OPCODE_GET;
    head->key_length       = htons((uint16_t)len);
    head->body_length      = htonl(len);

    msg->last = ngx_cpymem(msg->pos + sizeof(*head), key, len);

    return msg;
}

static ngx_buf_t *
ngx_ssl_session_memcached_delete(ngx_ssl_session_cache_ctx_t *cache_ctx, const u_char *key, int len)
{
    ngx_buf_t                   *msg;
    ngx_memcached_msg_head_t     *head;

    msg = ngx_ssl_session_cache_get_buf(cache_ctx,
             sizeof(ngx_memcached_msg_head_t) + len);
    if (msg == NULL) {
        return NULL; 
    }

    head = (ngx_memcached_msg_head_t*)msg->start;

    ngx_memzero(head, sizeof(*head));

    head->magic            = 0x80;
    head->opcode           = MEMCACHED_OPCODE_DEL;
    head->key_length       = htons((uint16_t)len);
    head->body_length      = htonl(len);

    msg->last = ngx_cpymem(msg->pos + sizeof(*head), key, len);

    return msg;
}

static ngx_buf_t *
ngx_ssl_session_memcached_check(ngx_ssl_session_cache_ctx_t *cache_ctx)
{
    ngx_buf_t                    *msg;
    ngx_memcached_msg_head_t     *head;

    msg = ngx_ssl_session_cache_get_buf(cache_ctx,
             sizeof(ngx_memcached_msg_head_t));
    if (msg == NULL) {
        return NULL; 
    }

    head = (ngx_memcached_msg_head_t*)msg->start;

    ngx_memzero(head, sizeof(*head));

    head->magic            = 0x80;
    head->opcode           = MEMCACHED_OPCODE_CHK;

    msg->last += sizeof(*head);

    return msg;
}

static ngx_int_t
ngx_ssl_session_memcached_parse(ngx_buf_t *in, ngx_ssl_session_cache_node_t *node)
{
    ngx_memcached_msg_head_t     head;
    ngx_int_t                    status;

    if ((size_t)(in->last - in->pos) < sizeof(head)) {
        return NGX_SSL_SESSION_CACHE_PARSE_MSG_MORE_DATA; 
    }

    ngx_memcpy(&head, in->pos, sizeof(head));

    if (head.magic != 0x81) {
        return NGX_SSL_SESSION_CACHE_PARSE_MSG_PROTO_ERR; 
    }

    head.v.status = ntohs(head.v.status);
    if (head.v.status != 0 ) {
        status = head.v.status;
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "ssl session memcached response status[%d]", status );
    }

    head.key_length  = ntohs(head.key_length);
    head.body_length = ntohl(head.body_length);

    switch (head.opcode) {
        
    case MEMCACHED_OPCODE_GET:  

        if (node->msg_type != NGX_SSL_SESSION_CACHE_MSG_TYPE_GET) {
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_TYPE_ERR; 
        }

        if ((size_t)(in->last - in->pos) < sizeof(head) + head.body_length) {
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_MORE_DATA; 
        }

        in->pos += sizeof(head);

        if (head.v.status == 0 ) {
            node->session.data = in->pos + head.extras_length;
            node->session.len  = head.body_length - head.extras_length;
        }

        in->pos += head.body_length;

        return NGX_SSL_SESSION_CACHE_PARSE_MSG_OK;

    case MEMCACHED_OPCODE_SET:  

        if (node->msg_type != NGX_SSL_SESSION_CACHE_MSG_TYPE_SET) {
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_TYPE_ERR; 
        }

        in->pos += sizeof(head) + head.body_length;

        return NGX_SSL_SESSION_CACHE_PARSE_MSG_OK;

    case MEMCACHED_OPCODE_DEL:  

        if (node->msg_type != NGX_SSL_SESSION_CACHE_MSG_TYPE_DEL) {
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_TYPE_ERR; 
        }

        in->pos += sizeof(head) + head.body_length;

        return NGX_SSL_SESSION_CACHE_PARSE_MSG_OK;

    case MEMCACHED_OPCODE_CHK:

        if (node->msg_type != NGX_SSL_SESSION_CACHE_MSG_TYPE_CHECK) {
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_TYPE_ERR; 
        }

        in->pos += sizeof(head) + head.body_length;

        return NGX_SSL_SESSION_CACHE_PARSE_MSG_OK;

    case MEMCACHED_OPCODE_ATH:  

        if (node->msg_type != NGX_SSL_SESSION_CACHE_MSG_TYPE_AUTH) {
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_TYPE_ERR; 
        }

        if (head.v.status != 0) {
            ngx_str_t    auth_error;
                
            auth_error.data = in->pos + sizeof(head);
            auth_error.len  = head.body_length;
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "ssl session memcached response status[%V]", &auth_error);
            return NGX_SSL_SESSION_CACHE_PARSE_MSG_STATUS_ERR;
        }


        in->pos += sizeof(head) + head.body_length;

        return NGX_SSL_SESSION_CACHE_PARSE_MSG_OK;

    default:
        return NGX_SSL_SESSION_CACHE_PARSE_MSG_TYPE_ERR;
    }
}

static ngx_ssl_session_cache_method_t *
ngx_ssl_session_cache_int_module(ngx_pool_t *pool, ngx_uint_t *default_port)
{
    ngx_ssl_session_cache_method_t   *method;

    method = ngx_pcalloc(pool, sizeof(*method));
    if (method == NULL) {
        return NULL; 
    }

    method->auth   = ngx_ssl_session_memcached_auth;
    method->set    = ngx_ssl_session_memcached_set;
    method->get    = ngx_ssl_session_memcached_get;
    method->delete = ngx_ssl_session_memcached_delete;
    method->check  = ngx_ssl_session_memcached_check;
    method->parse  = ngx_ssl_session_memcached_parse;

    *default_port = 11211;

    return method;
}
