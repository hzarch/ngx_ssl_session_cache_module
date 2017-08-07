#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ssl_session_cache_module.h"

#define CACHE_CONNECTED        1
#define CACHE_NOT_CONNECTED    2

static void
ngx_ssl_session_cache_write_data();
static void
ngx_ssl_session_cache_rehandshake(ngx_connection_t *c);

#define NGX_CACHE_UNLIMITED -2

#define NGX_CACHE_BUF_MIN_SIZE   256

#define ngx_ssl_session_cache_free_node(ctx, n) do {    \
    (n)->out = (ngx_buf_t*)(ctx)->free_node;   \
    (ctx)->free_node = (n); } while(0);

#define ngx_ssl_session_cache_free_buf(ctx, n) do {    \
    (n)->out->pos = (u_char*)(ctx)->free_out_buf;   \
    (ctx)->free_out_buf = (n)->out; } while(0);

ngx_uint_t
ngx_ssl_session_cache_get_size_len(ngx_uint_t size)
{
    ngx_uint_t count = 0;
    while(size){
        count++;
        size/=10;
    }
    return count;
}

ngx_buf_t *
ngx_ssl_session_cache_get_buf(ngx_ssl_session_cache_ctx_t *cache_ctx, size_t size)
{
    ngx_buf_t  *b;
    ngx_buf_t **buf;

    if (size < NGX_CACHE_BUF_MIN_SIZE ) {
        size = NGX_CACHE_BUF_MIN_SIZE; 
    }

    for (buf = &cache_ctx->free_out_buf; *buf; buf = (ngx_buf_t**)&b->pos) {
        b = *buf;
        if (size <= (size_t)(b->end - b->start)){

            *buf =(ngx_buf_t*) b->pos;

            b->pos = b->start;
            b->last = b->start;

            return b;
        }
    }

    b = ngx_create_temp_buf(cache_ctx->pool, size);
    if (!b) {
        ngx_log_error(NGX_LOG_CRIT, cache_ctx->log, 0, "[remote ssl session cache] malloc buf(%d) fail", size);
        return NULL; 
    }

    return b;
}

ngx_ssl_session_cache_node_t *
ngx_ssl_session_cache_get_node(ngx_ssl_session_cache_ctx_t *cache_ctx)
{
    ngx_ssl_session_cache_node_t   *n;

    if (cache_ctx->free_node != NULL) {
        n = cache_ctx->free_node; 
        cache_ctx->free_node = (ngx_ssl_session_cache_node_t*)n->out;

        return n;
    }

    n = ngx_pcalloc(cache_ctx->pool, sizeof(ngx_ssl_session_cache_node_t));
    if (!n) {
        ngx_log_error(NGX_LOG_CRIT, cache_ctx->log, 0, "[remote ssl session cache] malloc node fail");
        return NULL; 
    }

    return n;
}

static ngx_int_t
ngx_ssl_session_cache_auth(ngx_ssl_session_cache_ctx_t *cache_ctx, const u_char *auth, int len)
{
    ngx_ssl_session_cache_node_t *node;

    node = ngx_ssl_session_cache_get_node(cache_ctx);
    if (node == NULL) {
        return NGX_ERROR;
    }

    node->out = cache_ctx->conf->cache_method->auth(cache_ctx, auth, len);
    if (node->out == NULL) {
        ngx_ssl_session_cache_free_node(cache_ctx, node);
        return NGX_ERROR;
    }

    node->msg_type = NGX_SSL_SESSION_CACHE_MSG_TYPE_AUTH;
    node->c = NULL;
    node->seq = 0;
    cache_ctx->queue_num++;

    ngx_queue_insert_tail(&cache_ctx->write_queue, &node->queue);

    ngx_ssl_session_cache_write_data(cache_ctx);

    return NGX_OK;
}

static ngx_int_t
ngx_ssl_session_cache_get(ngx_ssl_session_cache_ctx_t *cache_ctx, ngx_connection_t *c, const u_char *id, int id_len)
{
    ngx_ssl_session_cache_node_t *node;

    if (cache_ctx->conf->queue_depth != NGX_CACHE_UNLIMITED && cache_ctx->queue_num >= cache_ctx->conf->queue_depth) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cache_ctx->log, 0,
                "[remote ssl session cache] queue size exceed max size %d", cache_ctx->conf->queue_depth);
        return NGX_ERROR;
    }

    node = ngx_ssl_session_cache_get_node(cache_ctx);
    if (node == NULL) {
        return NGX_ERROR; 
    }

    node->out = cache_ctx->conf->cache_method->get(cache_ctx, id, id_len);
    if (node->out == NULL){
        ngx_ssl_session_cache_free_node(cache_ctx, node);

        return NGX_ERROR;
    }

    node->msg_type     = NGX_SSL_SESSION_CACHE_MSG_TYPE_GET;
    node->c            = c;
    node->seq          = c->number;
    node->session.data = NULL;
    node->session.len  = 0;

    cache_ctx->queue_num++;

    ngx_queue_insert_tail(&cache_ctx->write_queue, &node->queue);

    ngx_ssl_session_cache_write_data(cache_ctx);

    return NGX_OK;
}

ngx_int_t
ngx_ssl_session_cache_set(ngx_ssl_session_cache_ctx_t *cache_ctx, ngx_connection_t *c,
    const u_char *id, int id_len, const u_char *sess, int sess_len)
{
    ngx_ssl_session_cache_node_t *node = NULL;

    if (cache_ctx->conf->queue_depth != NGX_CACHE_UNLIMITED && cache_ctx->queue_num >= cache_ctx->conf->queue_depth) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cache_ctx->log, 0,
                "[remote ssl session cache] queue size exceed max size %d", cache_ctx->conf->queue_depth);
        return NGX_ERROR;
    }

    node = ngx_ssl_session_cache_get_node(cache_ctx);
    if (node == NULL) {
        return NGX_ERROR; 
    }

    node->out = cache_ctx->conf->cache_method->set(cache_ctx, id, id_len, sess,
            sess_len, cache_ctx->conf->session_timeout);
    if (node->out == NULL ){
        ngx_ssl_session_cache_free_node(cache_ctx, node);

        return NGX_ERROR;
    }

    node->msg_type = NGX_SSL_SESSION_CACHE_MSG_TYPE_SET;
    node->c = c;
    node->seq = c->number;
    cache_ctx->queue_num++;

    ngx_queue_insert_tail(&cache_ctx->write_queue, &node->queue);

    ngx_ssl_session_cache_write_data(cache_ctx);

    return NGX_OK;
}

static void
ngx_ssl_session_cache_check(ngx_ssl_session_cache_ctx_t *cache_ctx)
{
    ngx_ssl_session_cache_node_t *node;

    node = ngx_ssl_session_cache_get_node(cache_ctx);
    if (node == NULL) {
        return; 
    }

    node->out = cache_ctx->conf->cache_method->check(cache_ctx);
    if (node->out == NULL) {
        ngx_ssl_session_cache_free_node(cache_ctx, node);
        return; 
    }

    node->msg_type = NGX_SSL_SESSION_CACHE_MSG_TYPE_CHECK;

    cache_ctx->queue_num++;
    ngx_queue_insert_tail(&cache_ctx->write_queue, &node->queue);

    ngx_ssl_session_cache_write_data(cache_ctx);

    return;
}

static void
ngx_ssl_session_cache_delete(ngx_ssl_session_cache_ctx_t *cache_ctx, const u_char *key, int len)
{
    ngx_ssl_session_cache_node_t *node;

    node = ngx_ssl_session_cache_get_node(cache_ctx);
    if (node == NULL) {
        return; 
    }

    node->out = cache_ctx->conf->cache_method->delete(cache_ctx, key, len);
    if (node->out == NULL) {
        ngx_ssl_session_cache_free_node(cache_ctx, node);
        return;
    }

    node->msg_type = NGX_SSL_SESSION_CACHE_MSG_TYPE_DEL;
    node->c        = NULL;
    node->seq      = 0;

    cache_ctx->queue_num++;
    ngx_queue_insert_tail(&cache_ctx->write_queue, &node->queue);

    ngx_ssl_session_cache_write_data(cache_ctx);

    return;
}

static void
ngx_ssl_session_cache_clear_resource(ngx_ssl_session_cache_ctx_t *cache_ctx)
{
    ngx_queue_t                      *q;
    ngx_ssl_session_cache_node_t     *node;

    cache_ctx->is_connected = CACHE_NOT_CONNECTED;

    if (cache_ctx->pc.connection) {
        ngx_close_connection(cache_ctx->pc.connection);
        cache_ctx->pc.connection = NULL;
    }

    if (cache_ctx->ev.timer_set) {
        ngx_del_timer(&cache_ctx->ev);
    }

    q = ngx_queue_head(&cache_ctx->write_queue);

    while (q != ngx_queue_sentinel(&cache_ctx->write_queue)) {

        node = ngx_queue_data(q, ngx_ssl_session_cache_node_t, queue);
        ngx_ssl_session_cache_free_buf(cache_ctx, node);

        q = ngx_queue_next(q);
    }

    if (!ngx_queue_empty(&cache_ctx->write_queue)) {

        ngx_queue_add(&cache_ctx->read_queue, &cache_ctx->write_queue);
    }

    while (1) {
        q = ngx_queue_head(&cache_ctx->read_queue);
        if (q == ngx_queue_sentinel(&cache_ctx->read_queue)) {
            break;
        }

        node = ngx_queue_data(q, ngx_ssl_session_cache_node_t, queue);

        if (node->msg_type == NGX_SSL_SESSION_CACHE_MSG_TYPE_GET && node->c->number == node->seq &&
                node->c->fd != -1) {
            ngx_ssl_session_cache_rehandshake(node->c);
        }

        ngx_queue_remove(&node->queue);

        ngx_ssl_session_cache_free_node(cache_ctx, node);
    }

    cache_ctx->queue_num = 0;
    ngx_queue_init(&cache_ctx->read_queue);
    ngx_queue_init(&cache_ctx->write_queue);

    cache_ctx->in.pos  = cache_ctx->in.start;
    cache_ctx->in.last = cache_ctx->in.start;

    ngx_log_error(NGX_LOG_CRIT, cache_ctx->log, 0, "[remote ssl session cache] : close connection, clear resource");
} 

static void
ngx_ssl_session_cache_clear_resource_add_timer(ngx_ssl_session_cache_ctx_t *cache_ctx)
{
    ngx_ssl_session_cache_clear_resource(cache_ctx);

    ngx_add_timer(&cache_ctx->ev, cache_ctx->conf->interval);
}

static ngx_int_t
ngx_ssl_session_cache_check_need_exit(ngx_ssl_session_cache_ctx_t *cache_ctx)
{
    if (ngx_terminate || ngx_exiting || ngx_quit) {
        ngx_ssl_session_cache_clear_resource(cache_ctx);
        return 1;
    }
    return 0;
}

static ngx_int_t
ngx_ssl_session_cache_process_buffer(ngx_ssl_session_cache_ctx_t *cache_ctx)
{
    ngx_queue_t                         *q;
    ngx_ssl_session_cache_node_t        *node;
    ngx_int_t                            rc;

    if (ngx_queue_empty(&cache_ctx->read_queue)) {
        return NGX_SSL_SESSION_CACHE_PARSE_MSG_PROTO_ERR; 
    }

    while (1) {

        q = ngx_queue_head(&cache_ctx->read_queue);
        if (q == ngx_queue_sentinel(&cache_ctx->read_queue)) {
            return NGX_OK;
        }

        node = ngx_queue_data(q, ngx_ssl_session_cache_node_t, queue);

        rc = cache_ctx->conf->cache_method->parse(&cache_ctx->in, node);
        if (rc == NGX_SSL_SESSION_CACHE_PARSE_MSG_MORE_DATA) {
            return NGX_AGAIN; 
        } else if(rc < 0 ) {
            return NGX_ERROR; 
        }

        if (node->msg_type == NGX_SSL_SESSION_CACHE_MSG_TYPE_GET &&
                node->c->number == node->seq  && node->c->fd != -1) {
            ngx_ssl_session_cache_rehandshake(node->c);
        }

        ngx_queue_remove(&node->queue);
        cache_ctx->queue_num--;
        ngx_ssl_session_cache_free_node(cache_ctx, node);
    }
}

static void
ngx_ssl_session_cache_read_handler(ngx_event_t *event)
{
    ngx_ssl_session_cache_ctx_t   *cache_ctx;
    ngx_connection_t              *c;
    ngx_uint_t                     n, remain;
    ssize_t                        size;

    c         = event->data;
    cache_ctx = c->data;

    if (ngx_ssl_session_cache_check_need_exit(cache_ctx)) {
        return;
    }

    if (event->timedout) {
        goto failed;
    }

    if (event->timer_set) {
        ngx_del_timer(event);
    }

    while (1) {
        n = cache_ctx->in.end - cache_ctx->in.last;

        if (n == 0) {
            if (cache_ctx->in.pos != cache_ctx->in.start) {

                remain = cache_ctx->in.last - cache_ctx->in.pos;
                ngx_memcpy(cache_ctx->in.start, cache_ctx->in.pos, remain);
                cache_ctx->in.pos = cache_ctx->in.start;
                cache_ctx->in.last = cache_ctx->in.pos + remain;
                n = cache_ctx->in.end - cache_ctx->in.last;
            } else {

                if( ngx_ssl_session_cache_process_buffer(cache_ctx) == NGX_ERROR) {
                    goto failed; 
                }
            }
        }

        size = c->recv(c, cache_ctx->in.last, n);

        if (size == NGX_AGAIN) {

            if (!ngx_queue_empty(&cache_ctx->read_queue)) {
                ngx_add_timer(event, cache_ctx->conf->proc_timeout);
            }

            return;
        } else if(size < 1){

            goto failed;
        }

        cache_ctx->in.last += size;

        if (ngx_ssl_session_cache_process_buffer(cache_ctx) == NGX_ERROR) {
            goto failed; 
        }
    }

failed:
    ngx_ssl_session_cache_clear_resource_add_timer(cache_ctx);
}

static void
ngx_ssl_session_cache_write_data(ngx_ssl_session_cache_ctx_t *cache_ctx)
{
    ngx_queue_t                        *q;
    ngx_ssl_session_cache_node_t       *node;
    ssize_t                             size;
    ngx_connection_t                   *c;

    c = cache_ctx->pc.connection;

    if (ngx_queue_empty(&cache_ctx->write_queue)) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_ssl_session_cache_clear_resource_add_timer(cache_ctx);
        }

        return;
    }

    while (1) {

        q = ngx_queue_head(&cache_ctx->write_queue);

        if (q == ngx_queue_sentinel(&cache_ctx->write_queue)) {

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_ssl_session_cache_clear_resource_add_timer(cache_ctx);
                return;
            }

            goto DONE;
        }

        node = ngx_queue_data(q, ngx_ssl_session_cache_node_t, queue);

        while (node->out->pos < node->out->last) {
            size = c->send(c, node->out->pos, node->out->last - node->out->pos);

            if (size >= 0) {
                node->out->pos += size;
            } else if (size == NGX_AGAIN) {

                ngx_add_timer(c->write, cache_ctx->conf->proc_timeout);

                if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                    ngx_ssl_session_cache_clear_resource_add_timer(cache_ctx);
                    return;
                }

                goto DONE;
            } else {
                return ngx_ssl_session_cache_clear_resource_add_timer(cache_ctx);
            }
        }

        ngx_ssl_session_cache_free_buf(cache_ctx, node);

        ngx_queue_remove(&node->queue);
        ngx_queue_insert_tail(&cache_ctx->read_queue, &node->queue);
    }

DONE:

    if (!c->read->timer_set) {
        ngx_add_timer(c->read, cache_ctx->conf->proc_timeout);
    }

    return;
}

static void
ngx_ssl_session_cache_write_handler(ngx_event_t *event)
{
    ngx_ssl_session_cache_ctx_t  *cache_ctx;

    cache_ctx = ((ngx_connection_t*)event->data)->data;

    if (ngx_ssl_session_cache_check_need_exit(cache_ctx)) {
        return;
    }

    if (event->timedout) {
        ngx_ssl_session_cache_clear_resource_add_timer(cache_ctx);
        return;
    }

    cache_ctx->is_connected = CACHE_CONNECTED;

    if (event->timer_set) {
        ngx_del_timer(event);
    }

    ngx_ssl_session_cache_write_data(cache_ctx);
}

static void
ngx_ssl_session_cache_auth_handler(ngx_event_t *event)
{
    ngx_ssl_session_cache_ctx_t  *cache_ctx;

    cache_ctx = ((ngx_connection_t*)event->data)->data;

    if (ngx_ssl_session_cache_check_need_exit(cache_ctx)) {
        return;
    }

    if (event->timedout) {
        ngx_ssl_session_cache_clear_resource_add_timer(cache_ctx);
        return;
    }

    cache_ctx->is_connected = CACHE_CONNECTED;

    if (event->timer_set) {
        ngx_del_timer(event);
    }

    event->handler = ngx_ssl_session_cache_write_handler;

    if (ngx_ssl_session_cache_auth(cache_ctx, cache_ctx->conf->auth.data, cache_ctx->conf->auth.len) != NGX_OK) {
        ngx_ssl_session_cache_clear_resource_add_timer(cache_ctx);
        return; 
    }

    return;
}

static void
ngx_ssl_session_cache_connect(ngx_event_t *ev)
{
    ngx_ssl_session_cache_ctx_t  *cache_ctx;
    ngx_int_t               rc;
    ngx_uint_t              i;
    ngx_connection_t        *c;

    cache_ctx = ev->data;

    for (i = 0; i < cache_ctx->conf->url.naddrs; i++) {

        cache_ctx->pc.name        = &cache_ctx->conf->url.addrs[i].name;
        cache_ctx->pc.sockaddr    = cache_ctx->conf->url.addrs[i].sockaddr;
        cache_ctx->pc.socklen     = cache_ctx->conf->url.addrs[i].socklen;

        rc = ngx_event_connect_peer(&cache_ctx->pc);

        if (rc == NGX_ERROR || rc == NGX_DECLINED || rc == NGX_BUSY) {
            continue;
        }

        c                 = cache_ctx->pc.connection;
        c->data           = cache_ctx;
        c->log            = ev->log;
        c->read->log      = ev->log;
        c->write->log     = ev->log;
        c->write->handler = ngx_ssl_session_cache_write_handler;
        c->read->handler  = ngx_ssl_session_cache_read_handler;

        if (cache_ctx->conf->auth.len != 0) {
            c->write->handler = ngx_ssl_session_cache_auth_handler;
        }

        if (rc == NGX_AGAIN) {
            ngx_add_timer(c->write, cache_ctx->conf->proc_timeout);
            return;
        }

        if (rc == NGX_OK) {
            c->write->handler(ev);
            return;
        }

        break;
    }
}

static void
ngx_ssl_session_cache_time_handler(ngx_event_t *ev)
{
    ngx_ssl_session_cache_ctx_t   *cache_ctx;

    cache_ctx = ev->data;

    ngx_add_timer(&cache_ctx->ev, cache_ctx->conf->interval);

    if (cache_ctx->is_connected == CACHE_NOT_CONNECTED &&
           cache_ctx->pc.connection == NULL) {
        return ngx_ssl_session_cache_connect(ev);
    }

    if (cache_ctx->queue_num == 0 &&
           cache_ctx->pc.connection != NULL) {
        return ngx_ssl_session_cache_check(cache_ctx); 
    }
}

int
ngx_ssl_session_cache_new_session(ngx_ssl_session_cache_ctx_t *cache_ctx,
    ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
    ngx_connection_t          *c;
    u_char                    buf[NGX_SSL_MAX_SESSION_SIZE];
    unsigned int              session_id_length;
    int                       len;
    u_char                    *p, *session_id;

    if (cache_ctx->is_connected == CACHE_NOT_CONNECTED) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cache_ctx->log, 0,
                    "[remote ssl session cache] new session when cache is not connected");
        return 0; 
    }

    len = i2d_SSL_SESSION(sess, NULL);

    /* do not cache too big session */
    if (len > (int) NGX_SSL_MAX_SESSION_SIZE) {
        return 0;
    }

    p = buf;
    i2d_SSL_SESSION(sess, &p);

    c = ngx_ssl_get_connection(ssl_conn);

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
    session_id = (u_char *) SSL_SESSION_get_id(sess, &session_id_length);
#else
    session_id = sess->session_id;
    session_id_length = sess->session_id_length;
#endif

    ngx_ssl_session_cache_set(cache_ctx, c, session_id, session_id_length, buf, len);

    return 0;
}

static void
ngx_ssl_session_cache_rehandshake(ngx_connection_t *c)
{
    ngx_int_t rc;

    rc = ngx_ssl_handshake(c);

    if (rc == NGX_AGAIN) {
        ngx_reusable_connection(c, 0);
        return;
    }

    c->ssl->handler(c);

    return;
}

ngx_ssl_session_t *
ngx_ssl_session_cache_get_session(ngx_ssl_session_cache_ctx_t *cache_ctx,
    ngx_ssl_conn_t *ssl_conn, const u_char *id, int len, int *copy)
{
    ngx_connection_t              *c = NULL;
    ngx_ssl_session_t             *sess;
    ngx_ssl_session_cache_node_t  *node;
    ngx_queue_t                   *q;
    ngx_int_t                      rc;

    if (cache_ctx->is_connected == CACHE_NOT_CONNECTED) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cache_ctx->log, 0,
                    "[remote ssl session cache] get session when cache is not connected");
        return NULL; 
    }

    do {
        *copy = 0;

        sess = NULL;

        c = ngx_ssl_get_connection(ssl_conn);

        q = ngx_queue_head(&cache_ctx->read_queue);
        if (q == ngx_queue_sentinel(&cache_ctx->read_queue)) {
            goto GET;
        }

        node = ngx_queue_data(q, ngx_ssl_session_cache_node_t, queue);


        if (node->c != c || node->seq != c->number) {
GET:
            rc = ngx_ssl_session_cache_get(cache_ctx, c, id, len);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cache_ctx->log, 0, "[remote ssl session cache] : first get session, async get done, result [%i]", rc);

            if (rc == NGX_ERROR) {

                return NULL;  /*failed, new session*/
            } else {

                ASYNC_pause_job();
            }
        } else {

            if (node->session.len == 0 || node->session.data == NULL) {
                return NULL;
            }

            sess = d2i_SSL_SESSION(NULL, (const unsigned char**)&node->session.data, node->session.len);

            ngx_log_debug(NGX_LOG_DEBUG_HTTP, cache_ctx->log, 0, "[remote ssl session cache] : second get session done");

            return sess;
        }
    }while(1);

}

void
ngx_ssl_session_cache_remove_session(ngx_ssl_session_cache_ctx_t *cache_ctx,
                                ngx_ssl_session_t *sess)
{
    u_char          *session_id;
    unsigned int     id_len;

    if (cache_ctx->is_connected == CACHE_NOT_CONNECTED) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cache_ctx->log, 0,
                    "[remote ssl session cache] delete session when cache is not connected");
        return ; 
    }

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
    session_id = (u_char *) SSL_SESSION_get_id(sess, &id_len);
#else
    session_id = sess->session_id;
    id_len     = sess->session_id_length;
#endif

    ngx_ssl_session_cache_delete(cache_ctx, session_id, id_len);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, cache_ctx->log, 0, "[remote ssl session cache] : in ngx_ssl_session_cache_remove_session");
    return;
}

ngx_int_t
ngx_ssl_session_cache_add_timers(ngx_cycle_t *cycle, ngx_ssl_session_cache_conf_t *sccf)
{
    ngx_ssl_session_cache_ctx_t  *cache_ctx;

    if (sccf->onoff != NGX_SSL_SESSION_CACHE_ON) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "[remote ssl session cache] : store_sess off");
        return NGX_OK;
    }

    if (sccf->cache_ctx->pool != NULL) {
        return NGX_OK; 
    }

    cache_ctx = sccf->cache_ctx;

    cache_ctx->conf = sccf;

    cache_ctx->pool = ngx_create_pool(128 * 1024, cycle->log);
    if (cache_ctx->pool == NULL) {
        return NGX_ERROR;  
    }

    cache_ctx->in.start = ngx_palloc(cache_ctx->pool, 32 * 1024);
    if (cache_ctx->in.start == NULL ) {
        return NGX_ERROR; 
    }

    cache_ctx->in.pos  = cache_ctx->in.start;
    cache_ctx->in.last = cache_ctx->in.start;
    cache_ctx->in.end  = cache_ctx->in.start + 32 * 1024;

    cache_ctx->pc.get         = ngx_event_get_peer;
    cache_ctx->pc.log         = cycle->log;
    cache_ctx->pc.log_error   = NGX_ERROR_ERR;
    cache_ctx->is_connected   = CACHE_NOT_CONNECTED;
    cache_ctx->ev.handler     = ngx_ssl_session_cache_time_handler;
    cache_ctx->ev.log         = cycle->log;
    cache_ctx->ev.data        = cache_ctx;
    cache_ctx->log            = cycle->log;
    cache_ctx->queue_num      = 0;

    ngx_queue_init(&cache_ctx->read_queue);
    ngx_queue_init(&cache_ctx->write_queue);

    ngx_add_timer(&cache_ctx->ev, sccf->interval);

    return NGX_OK;
}

static  ngx_ssl_session_cache_method_t *
ngx_ssl_session_cache_type(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t *default_port)
{
    int                               i; 
    ngx_module_t                    **module;
    ngx_ssl_session_cache_module_t   *module_ctx;

    module = cf->cycle->modules;

    *default_port = 0;

    for (i = 0 ;module[i]; i++) {
        if (module[i]->type != NGX_RSSC_MODULE) {
            continue; 
        }

        module_ctx = module[i]->ctx;

        if (module_ctx->name.len != name->len ||
                ngx_strncmp(module_ctx->name.data, name->data, name->len)) {
            continue; 
        }

        return module_ctx->init(cf->pool, default_port);
    }

    return NULL;
}

char*
ngx_ssl_session_cache_conf(ngx_ssl_session_cache_conf_t *sccf, ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *value, s, addr = ngx_null_string, type;
    ngx_uint_t                      i, port, default_port, interval;
    ngx_msec_t                      timeout;
    ngx_int_t                       count, onoff;

    value = cf->args->elts;
    onoff = NGX_SSL_SESSION_CACHE_ON;

    port = 0;
    timeout = 1000;
    interval = 200;
    count = 5000;

    ngx_str_set(&type, "redis");

    if (sccf->onoff != NGX_CONF_UNSET) {
        return "is duplicate"; 
    }

    for (i = 1; i < cf->args->nelts; ++i) {
        if (ngx_strncmp(value[i].data, "addr=", 5) == 0) {
            addr.len = value[i].len - 5;
            addr.data = value[i].data + 5;
            continue;
        }

        if (ngx_strncmp(value[i].data, "port=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;
            port = ngx_atoi(s.data, s.len);
            if (port == 0) {
                goto invalid_param;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "auth=", 5) == 0) {
            sccf->auth.len = value[i].len - 5;
            sccf->auth.data = value[i].data + 5;
            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.len = value[i].len - 8;
            s.data = value[i].data + 8;
            timeout = ngx_atoi(s.data, s.len);
            if (timeout == 0) {
                goto invalid_param;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;
            interval = ngx_atoi(s.data, s.len);
            if (interval == 0) {
                goto invalid_param;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "count=", 6) == 0) {
            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            if (ngx_strlen("unlimited") == s.len && ngx_strncmp(s.data, "unlimited", s.len) == 0) {
                count = NGX_CACHE_UNLIMITED;
            } else {
                count = ngx_atoi(s.data, s.len);
                if (count <= 0) {
                    goto invalid_param;
                }
            }
            continue;
        }

        if (value[i].len == 3 && ngx_strncmp(value[i].data, "off", 3) == 0) {
            onoff = NGX_SSL_SESSION_CACHE_OFF;
            continue;
        }

        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {
            type.len = value[i].len - 5;
            type.data = value[i].data + 5;
            continue;
        }

        goto invalid_param;
    }

    if (onoff == NGX_SSL_SESSION_CACHE_OFF ) {
        sccf->onoff = NGX_SSL_SESSION_CACHE_OFF;
        return NGX_CONF_OK;
    }

    sccf->cache_method = ngx_ssl_session_cache_type(cf, &type, &default_port);
    if (sccf->cache_method == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "remote_ssl_session_cache init cache type[%V] fail", &type);
        return NGX_CONF_ERROR;
    }

    if (addr.len == 0 || addr.data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid ssl session cache param, remote_ssl_session_cache url empty");
        return NGX_CONF_ERROR;
    }

    if (port == 0 ) {
        port = default_port;
    }

    sccf->url.host = addr;
    sccf->url.port = port;
    sccf->proc_timeout = timeout;
    sccf->interval = interval;
    sccf->queue_depth = count;
    sccf->onoff = onoff;

    sccf->cache_ctx = ngx_pcalloc(cf->pool, sizeof(*sccf->cache_ctx));
    if (sccf->cache_ctx == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "remote_ssl_session_cache alloc memory fail");
        return NGX_CONF_ERROR;
    }

    if (ngx_inet_resolve_host(cf->pool, &sccf->url) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "parse addr failed, url: \"%V\"", &addr);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

invalid_param:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid remote_ssl_session_cache param \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}
