#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_ssl_session_cache_module.h"

static ngx_int_t
ngx_http_ssl_session_cache_init_process(ngx_cycle_t *cycle);
static void
ngx_http_ssl_session_cache_exit_process(ngx_cycle_t *cycle);
static void*
ngx_http_ssl_session_cache_create_srv_conf(ngx_conf_t *cf);
static char*
ngx_http_ssl_session_cache_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static char*
ngx_http_ssl_cache_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static int ngx_http_ssl_session_cache_conf_index = -1;

static ngx_command_t ngx_http_ssl_session_cache_commands[] = {
    {
        ngx_string("remote_ssl_session_cache"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_1MORE,
        ngx_http_ssl_cache_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_ssl_session_cache_module_ctx = {
    NULL,                                          /* preconfiguration */
    NULL,                                          /* postconfiguration */

    NULL,                                          /* create main configuration */
    NULL,                                          /* init main configuration */

    ngx_http_ssl_session_cache_create_srv_conf,    /* create server configuration */
    ngx_http_ssl_session_cache_merge_srv_conf,     /* merge server configuration */

    NULL,                                          /* create location configuration */
    NULL                                           /* merge location configuration */
};

ngx_module_t  ngx_http_ssl_session_cache_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_session_cache_module_ctx,     /* module context */
    ngx_http_ssl_session_cache_commands,        /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    ngx_http_ssl_session_cache_init_process,    /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    ngx_http_ssl_session_cache_exit_process,    /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_ssl_session_cache_ctx_t *
ngx_http_ssl_session_cache_get_ctx(ngx_ssl_conn_t *ssl_conn)
{
    ngx_ssl_session_cache_conf_t  *sccf;
    SSL_CTX                       *ssl_ctx;

    ssl_ctx = SSL_get_SSL_CTX(ssl_conn);

    sccf = SSL_CTX_get_ex_data(ssl_ctx, ngx_http_ssl_session_cache_conf_index);
    if (sccf == NULL) {
        return 0; 
    }

    return sccf->cache_ctx;
}

static int
ngx_http_ssl_session_cache_new_session(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
    ngx_ssl_session_cache_ctx_t *cache_ctx;

    cache_ctx = ngx_http_ssl_session_cache_get_ctx(ssl_conn);
    if (cache_ctx == NULL) {
        return 0; 
    }

    return ngx_ssl_session_cache_new_session(cache_ctx, ssl_conn, sess);
}

static ngx_ssl_session_t *
ngx_http_ssl_session_cache_get_session(ngx_ssl_conn_t *ssl_conn, const u_char *id,
    int len, int *copy)
{
    ngx_ssl_session_cache_ctx_t *cache_ctx;

    *copy = 0;

    cache_ctx = ngx_http_ssl_session_cache_get_ctx(ssl_conn);
    if (cache_ctx == NULL) {
        return NULL; 
    }

    return ngx_ssl_session_cache_get_session(cache_ctx, ssl_conn, id, len, copy);
}

static void
ngx_http_ssl_session_cache_remove_session(SSL_CTX *ssl_ctx, ngx_ssl_session_t *sess)
{
    ngx_ssl_session_cache_conf_t  *sccf;

    sccf = SSL_CTX_get_ex_data(ssl_ctx, ngx_http_ssl_session_cache_conf_index);
    if (sccf == NULL || sccf->cache_ctx == NULL) {
        return; 
    }

    return ngx_ssl_session_cache_remove_session(sccf->cache_ctx, sess);
}

static int
ngx_http_ssl_session_cache_set_openssl_cb(SSL_CTX *ssl_ctx)
{
    SSL_CTX_sess_set_new_cb(ssl_ctx, ngx_http_ssl_session_cache_new_session);
    SSL_CTX_sess_set_get_cb(ssl_ctx, ngx_http_ssl_session_cache_get_session);
    SSL_CTX_sess_set_remove_cb(ssl_ctx, ngx_http_ssl_session_cache_remove_session);

    return 1;
}

static ngx_int_t
ngx_http_ssl_session_cache_init_process(ngx_cycle_t *cycle)
{
    ngx_http_core_main_conf_t     *cmcf;
    ngx_http_core_srv_conf_t     **cscf;
    ngx_ssl_session_cache_conf_t  *sccf;
    ngx_uint_t                     i;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR; 
    }

    cscf = cmcf->servers.elts;
    for (i=0; i<cmcf->servers.nelts; i++) {
        sccf = cscf[i]->ctx->srv_conf[ngx_http_ssl_session_cache_module.ctx_index];
        if (sccf == NULL || sccf->cache_ctx == NULL || sccf->cache_ctx->pool) {
            continue; 
        }

        if (ngx_ssl_session_cache_add_timers(cycle, sccf) != NGX_OK) {
            ngx_http_ssl_session_cache_exit_process(cycle);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void
ngx_http_ssl_session_cache_exit_process(ngx_cycle_t *cycle)
{
    ngx_pool_t                    *p;
    ngx_http_core_main_conf_t     *cmcf;
    ngx_http_core_srv_conf_t     **cscf;
    ngx_ssl_session_cache_conf_t  *sccf;
    ngx_uint_t                     i;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);
    if (cmcf == NULL) {
        return ; 
    }

    cscf = cmcf->servers.elts;
    for (i=0; i<cmcf->servers.nelts; i++) {
        sccf = cscf[i]->ctx->srv_conf[ngx_http_ssl_session_cache_module.ctx_index];
        if (sccf == NULL || sccf->cache_ctx == NULL || sccf->cache_ctx->pool == NULL) {
            continue; 
        }

        p = sccf->cache_ctx->pool;

        ngx_destroy_pool(p);

        sccf->cache_ctx->pool = NULL;
    }
}

static void*
ngx_http_ssl_session_cache_create_srv_conf(ngx_conf_t *cf)
{
    ngx_ssl_session_cache_conf_t *sccf;

    sccf = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_session_cache_conf_t));
    if (sccf == NULL) {
        return NULL;
    }

    sccf->onoff        = NGX_CONF_UNSET;
    sccf->proc_timeout = NGX_CONF_UNSET_MSEC;
    sccf->interval     = NGX_CONF_UNSET_MSEC;
    sccf->queue_depth  = NGX_CONF_UNSET;
    sccf->cache_method = NGX_CONF_UNSET_PTR;
    sccf->cache_ctx    = NULL;

    ngx_str_null(&sccf->auth);

    return sccf;
}

static int
ngx_http_ssl_session_cache_listen_ssl(ngx_conf_t *cf)
{
    ngx_http_core_srv_conf_t       *cscf;
    ngx_http_core_main_conf_t      *cmcf;
    ngx_http_conf_port_t           *port;
    ngx_http_conf_addr_t           *addr;
    ngx_http_core_srv_conf_t      **server;
    ngx_uint_t                      i, j, k;
    int                             on = 0;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module); 
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    port = cmcf->ports->elts;
    for (i=0; i < cmcf->ports->nelts; i++) {

        addr = port[i].addrs.elts;
        for (j=0; j < port[i].addrs.nelts; j++) {

            server = addr[j].servers.elts; 
            for (k=0; k < addr[j].servers.nelts; k++) {
                if (server[k] != cscf) {
                    continue;
                }

                if (addr[j].opt.ssl) {
                    on = 1; 
                }
            }
        }
    }
    
    return on;
}

static char*
ngx_http_ssl_session_cache_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_ssl_session_cache_conf_t *prev = parent;
    ngx_ssl_session_cache_conf_t *conf = child;
    ngx_http_ssl_srv_conf_t      *sscf;
    long                          cache_mode;

    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

    if (!sscf->enable && !ngx_http_ssl_session_cache_listen_ssl(cf)) {
        conf->cache_ctx = NULL; 
        conf->onoff = NGX_SSL_SESSION_CACHE_OFF; 

        return NGX_CONF_OK;
    }

    if (conf->onoff == NGX_SSL_SESSION_CACHE_OFF || sscf->ssl.ctx == NULL) {
        conf->cache_ctx = NULL;

        return NGX_CONF_OK;
    }

    if (prev->onoff == NGX_CONF_UNSET && conf->onoff == NGX_CONF_UNSET) {
        conf->cache_ctx = NULL;
        conf->onoff = NGX_SSL_SESSION_CACHE_OFF; 

        return NGX_CONF_OK;
    }

    cache_mode = SSL_SESS_CACHE_NO_INTERNAL | SSL_SESS_CACHE_SERVER;

    SSL_CTX_set_mode(sscf->ssl.ctx, SSL_MODE_ASYNC);
    SSL_CTX_set_session_cache_mode(sscf->ssl.ctx, cache_mode);

    if (ngx_http_ssl_session_cache_conf_index == -1) {
        ngx_http_ssl_session_cache_conf_index =
            SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        if (ngx_http_ssl_session_cache_conf_index == -1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "SSL_get_ex_new_index() failed"); 
            return NGX_CONF_ERROR;
        }
    }

    if (SSL_CTX_set_ex_data(sscf->ssl.ctx, ngx_http_ssl_session_cache_conf_index,
                       conf) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "SSL_CTX_set_ex_data() failed"); 
        return NGX_CONF_ERROR;
    }

    ngx_http_ssl_session_cache_set_openssl_cb(sscf->ssl.ctx);

    conf->session_timeout = sscf->session_timeout;

    if (conf->onoff == NGX_SSL_SESSION_CACHE_ON) {
        return NGX_CONF_OK;
    }

    conf->onoff        = prev->onoff;
    conf->queue_depth  = prev->queue_depth;
    conf->proc_timeout = prev->proc_timeout;
    conf->interval     = prev->interval;
    conf->cache_ctx    = prev->cache_ctx; 
    conf->cache_method = prev->cache_method;
    conf->url          = prev->url;
    conf->auth         = prev->auth;

    return NGX_CONF_OK;
}

static char*
ngx_http_ssl_cache_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_ssl_session_cache_conf_t    *sccf;

    sccf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_session_cache_module);

    return ngx_ssl_session_cache_conf(sccf, cf, cmd, conf);
}
