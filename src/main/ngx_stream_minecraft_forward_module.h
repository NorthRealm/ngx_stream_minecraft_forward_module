#ifndef _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H_
#define _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H_

#include <ngx_core.h>

typedef struct {
    ngx_hash_t             hostname_map;
    ngx_hash_init_t        hostname_map_init;
    ngx_hash_keys_arrays_t hostname_map_keys; // `key`:`ngx_str_t *`, `value`:`u_char *`
    size_t                 hash_max_size;
    size_t                 hash_bucket_size;

    ngx_flag_t             replace_on_ping;
    ngx_flag_t             disconnect_on_nomatch;
    ngx_flag_t             enabled;
} nsmfm_srv_conf_t;

extern ngx_module_t ngx_stream_minecraft_forward_module;

#endif
