extern "C"
{
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_hash.h>
#include <ngx_stream.h>
#include "ngx_stream_minecraft_forward_module.h"
}

static void *nsmfm_create_srv_conf(ngx_conf_t *cf);
static char *nsmfm_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf);

static char *nsmfm_srv_conf_minecraft_server_hostname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#define _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_MAX_SIZE_ 512
#define _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_BUCKET_SIZE_ 64

static ngx_command_t nsmfm_directives[] = {
    {ngx_string("minecraft_server_forward"),
     NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(nsmfm_srv_conf_t, enabled),
     NULL},
    {ngx_string("minecraft_server_hostname"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE23,
     nsmfm_srv_conf_minecraft_server_hostname,
     NGX_STREAM_SRV_CONF_OFFSET,
     0,
     NULL},
    {ngx_string("minecraft_server_hostname_hash_max_size"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(nsmfm_srv_conf_t, hash_max_size),
     NULL},
    {ngx_string("minecraft_server_hostname_hash_bucket_size"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(nsmfm_srv_conf_t, hash_bucket_size),
     NULL},
    {ngx_string("minecraft_server_hostname_disconnect_on_nomatch"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(nsmfm_srv_conf_t, disconnect_on_nomatch),
     NULL},
    {ngx_string("minecraft_server_hostname_replace_on_ping"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(nsmfm_srv_conf_t, replace_on_ping),
     NULL},
    ngx_null_command,
};

static ngx_stream_module_t nsmfm_conf_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    nsmfm_create_srv_conf, /* create server configuration */
    nsmfm_merge_srv_conf   /* merge server configuration */
};

ngx_module_t ngx_stream_minecraft_forward_module = {
    NGX_MODULE_V1,
    &nsmfm_conf_ctx,       /* module conf context */
    nsmfm_directives,      /* module directives */
    NGX_STREAM_MODULE,     /* module type */
    NULL,                  /* init master */
    NULL,                  /* init module */
    NULL,                  /* init process */
    NULL,                  /* init thread */
    NULL,                  /* exit thread */
    NULL,                  /* exit process */
    NULL,                  /* exit master */
    NGX_MODULE_V1_PADDING  /* No padding */
};

static void *nsmfm_create_srv_conf(ngx_conf_t *cf) {
    ngx_int_t         rc;
    nsmfm_srv_conf_t *conf;

    conf = (nsmfm_srv_conf_t *) ngx_pcalloc(cf->pool, sizeof(nsmfm_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->disconnect_on_nomatch = NGX_CONF_UNSET;

    conf->hostname_map_init.hash = &conf->hostname_map;
    conf->hostname_map_init.key = ngx_hash_key_lc;
    conf->hostname_map_init.name = (char *)"minecraft_server_hostname";
    conf->hostname_map_init.pool = cf->pool;
    conf->hostname_map_init.temp_pool = cf->temp_pool;
    
    conf->hash_max_size = NGX_CONF_UNSET_SIZE;
    conf->hash_bucket_size = NGX_CONF_UNSET_SIZE;
    
    conf->hostname_map_keys.pool = cf->pool;
    conf->hostname_map_keys.temp_pool = cf->temp_pool;
    rc = ngx_hash_keys_array_init(&conf->hostname_map_keys, NGX_HASH_SMALL);
    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "There's a problem initializing hash keys array");
        return NULL;
    }

    conf->replace_on_ping = NGX_CONF_UNSET;

    return conf;
}

static char *nsmfm_srv_conf_minecraft_server_hostname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_int_t   rc;
    ngx_str_t  *values;
    ngx_str_t  *read_key;
    ngx_str_t  *read_val;

    u_char     *val;

    nsmfm_srv_conf_t *sc = (nsmfm_srv_conf_t *) conf;

    values = (ngx_str_t *) cf->args->elts;

    read_key = &values[1];
    read_val = &values[2];

#if (NGX_DEBUG)
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "minecraft_server_hostname: %s - %s", read_key->data, read_val->data);
#endif

    val = (u_char *) ngx_pnalloc(cf->pool, (read_val->len + 1) * sizeof(u_char));
    ngx_memcpy(val, read_val->data, read_val->len);
    val[read_val->len] = 0;

    rc = ngx_hash_add_key(&sc->hostname_map_keys, read_key, val, NGX_HASH_READONLY_KEY);
    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "There's a problem adding hash key, possibly because of duplicate entry");
        return (char *)NGX_CONF_ERROR;
    }

    return (char *)NGX_CONF_OK;
}

static char *nsmfm_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf) {
    ngx_int_t          rc;
    nsmfm_srv_conf_t  *pconf;
    nsmfm_srv_conf_t  *cconf;

    ngx_str_t         *key;
    ngx_uint_t         hashed_key;
    u_char            *val;

    pconf = (nsmfm_srv_conf_t *) prev;
    cconf = (nsmfm_srv_conf_t *) conf;

    ngx_conf_merge_value(cconf->enabled, pconf->enabled, 0);
    ngx_conf_merge_value(cconf->disconnect_on_nomatch, pconf->disconnect_on_nomatch, 0);
    ngx_conf_merge_value(cconf->replace_on_ping, pconf->replace_on_ping, 1);

    ngx_conf_merge_size_value(pconf->hash_max_size,
        NGX_CONF_UNSET_SIZE, _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_MAX_SIZE_);

    ngx_conf_merge_size_value(pconf->hash_bucket_size,
        NGX_CONF_UNSET_SIZE, _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_BUCKET_SIZE_);

    ngx_conf_merge_size_value(cconf->hash_max_size, pconf->hash_max_size,
        _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_MAX_SIZE_);

    ngx_conf_merge_size_value(cconf->hash_bucket_size, pconf->hash_bucket_size,
        _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_BUCKET_SIZE_);

    pconf->hostname_map_init.max_size = pconf->hash_max_size;
    pconf->hostname_map_init.bucket_size = ngx_align(pconf->hash_bucket_size, ngx_cacheline_size);

    rc = ngx_hash_init(&pconf->hostname_map_init,
                       (ngx_hash_key_t *)pconf->hostname_map_keys.keys.elts,
                       pconf->hostname_map_keys.keys.nelts);

    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "There's a problem initializing hash table in stream context");
        return (char *)NGX_CONF_ERROR;
    }

    // MERGE HASH TABLE
    // TODO: Can it be improved further?
    for (ngx_uint_t i = 0; i < pconf->hostname_map_keys.keys.nelts; ++i) {
        key = &((ngx_hash_key_t *)pconf->hostname_map_keys.keys.elts + i)->key;

        hashed_key = ngx_hash_key(key->data, key->len);

        val = (u_char *)ngx_hash_find(&pconf->hostname_map, hashed_key, key->data, key->len);

        if (val == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "A hash key previously in stream context becomes missing?! This should not happen");
            return (char *)NGX_CONF_ERROR;
        }
#if (NGX_DEBUG)
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "Merging: minecraft_server_hostname: %s - %s", key->data, val);
#endif
        rc = ngx_hash_add_key(&cconf->hostname_map_keys, key, val, NGX_HASH_READONLY_KEY);
        if (rc != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "There's a problem merging hash table%s",
                               rc == NGX_BUSY ? " because of duplicate entry" : "");
            return (char *)NGX_CONF_ERROR;
        }
    }

    cconf->hostname_map_init.max_size = cconf->hash_max_size;
    cconf->hostname_map_init.bucket_size = ngx_align(cconf->hash_bucket_size, ngx_cacheline_size);

    rc = ngx_hash_init(&cconf->hostname_map_init,
                       (ngx_hash_key_t *)cconf->hostname_map_keys.keys.elts,
                       cconf->hostname_map_keys.keys.nelts);

    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "There's a problem initializing hash table in server context");
        return (char *)NGX_CONF_ERROR;
    }

    return (char *)NGX_CONF_OK;
}
