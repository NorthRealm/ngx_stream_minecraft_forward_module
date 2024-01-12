#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hash.h>
#include <ngx_stream.h>

typedef struct {
    ngx_hash_t domain_map;
    ngx_hash_init_t domain_map_init;
    ngx_hash_keys_arrays_t domain_map_keys;

    size_t hash_max_size;
    size_t hash_bucket_size;

    ngx_flag_t enabled;
} ngx_stream_minecraft_forward_module_srv_conf_t;

typedef struct {
    u_short phase; /* 0: Handshake, 1: Status, 2: Login start */
    ngx_int_t protocol_num;
    u_char *remote_hostname;
    u_int remote_hostname_len;
    u_short remote_port;

    u_int handshake_varint_byte_len;
    u_int handshake_len;
    ngx_chain_t *filter_free;
    ngx_chain_t *filter_busy;

    u_int expected_packet_len;
    u_char *pos;
} ngx_stream_minecraft_forward_module_ctx_t;

ngx_stream_filter_pt ngx_stream_next_filter;

static void *ngx_stream_minecraft_forward_module_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_minecraft_forward_module_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf);

static char *ngx_stream_minecraft_forward_module_srv_conf_minecraft_server_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_stream_minecraft_forward_module_preread(ngx_stream_session_t *s);
ngx_int_t ngx_stream_minecraft_forward_module_handshake_preread(ngx_stream_session_t *s);
ngx_int_t ngx_stream_minecraft_forward_module_loginstart_preread(ngx_stream_session_t *s);

static ngx_int_t ngx_stream_minecraft_forward_module_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain, ngx_uint_t from_upstream);

static ngx_int_t ngx_stream_minecraft_forward_module_post_init(ngx_conf_t *cf);

static ngx_command_t ngx_stream_minecraft_forward_module_directives[] = {
    {ngx_string("minecraft_server_forward"), /* Indicate a server block that proxies minecraft tcp connections. */
     NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_minecraft_forward_module_srv_conf_t, enabled),
     NULL},
    {ngx_string("minecraft_server_domain"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2,
     ngx_stream_minecraft_forward_module_srv_conf_minecraft_server_domain,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_minecraft_forward_module_srv_conf_t, domain_map),
     NULL},
    {ngx_string("minecraft_server_domain_hash_max_size"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_minecraft_forward_module_srv_conf_t, hash_max_size),
     NULL},
    {ngx_string("minecraft_server_domain_hash_bucket_size"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_minecraft_forward_module_srv_conf_t, hash_bucket_size),
     NULL},
    ngx_null_command /* END */
};

ngx_stream_module_t ngx_stream_minecraft_forward_module_conf_ctx = {
    NULL,                                          /* preconfiguration */
    ngx_stream_minecraft_forward_module_post_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    ngx_stream_minecraft_forward_module_create_srv_conf, /* create server configuration */
    ngx_stream_minecraft_forward_module_merge_srv_conf   /* merge server configuration */
};

ngx_module_t ngx_stream_minecraft_forward_module = {
    NGX_MODULE_V1,
    &ngx_stream_minecraft_forward_module_conf_ctx,  /* module conf context */
    ngx_stream_minecraft_forward_module_directives, /* module directives */
    NGX_STREAM_MODULE,                              /* module type */
    NULL,                                           /* init master */
    NULL,                                           /* init module */
    NULL,                                           /* init process */
    NULL,                                           /* init thread */
    NULL,                                           /* exit thread */
    NULL,                                           /* exit process */
    NULL,                                           /* exit master */
    NGX_MODULE_V1_PADDING                           /* No padding*/
};

static void *ngx_stream_minecraft_forward_module_create_srv_conf(ngx_conf_t *cf) {
    ngx_stream_minecraft_forward_module_srv_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_minecraft_forward_module_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enabled = NGX_CONF_UNSET;

    conf->domain_map_init.hash = &conf->domain_map;
    conf->domain_map_init.key = ngx_hash_key_lc;
    conf->domain_map_init.name = "minecraft_server_domain";
    conf->domain_map_init.pool = cf->pool;
    conf->domain_map_init.temp_pool = cf->temp_pool;
    conf->hash_max_size = NGX_CONF_UNSET_SIZE;
    conf->hash_bucket_size = NGX_CONF_UNSET_SIZE;
    conf->domain_map_keys.pool = cf->pool;
    conf->domain_map_keys.temp_pool = cf->temp_pool;
    ngx_int_t rc = ngx_hash_keys_array_init(&conf->domain_map_keys, NGX_HASH_SMALL);
    if (rc != NGX_OK) {
        ngx_pfree(cf->pool, conf);
        return NULL;
    }

    return conf;
}

static char *ngx_stream_minecraft_forward_module_srv_conf_minecraft_server_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_stream_minecraft_forward_module_srv_conf_t *sc = conf;

    ngx_str_t *values;
    values = cf->args->elts;
    ngx_int_t rc;

    rc = ngx_hash_add_key(&sc->domain_map_keys, &values[1], values[2].data, 0);
    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, "There's a problem adding hash key, possibly because of duplicate entry");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *ngx_stream_minecraft_forward_module_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf) {
    ngx_stream_minecraft_forward_module_srv_conf_t *pconf = prev;
    ngx_stream_minecraft_forward_module_srv_conf_t *cconf = conf;

    ngx_conf_merge_value(cconf->enabled, pconf->enabled, 0);
    ngx_conf_merge_size_value(pconf->hash_max_size, NGX_CONF_UNSET_SIZE, 512);
    ngx_conf_merge_size_value(pconf->hash_bucket_size, NGX_CONF_UNSET_SIZE, 64);
    ngx_conf_merge_size_value(cconf->hash_max_size, pconf->hash_max_size, 512);
    ngx_conf_merge_size_value(cconf->hash_bucket_size, pconf->hash_bucket_size, 64);

    pconf->domain_map_init.max_size = pconf->hash_max_size;
    pconf->domain_map_init.bucket_size = ngx_align(pconf->hash_bucket_size, ngx_cacheline_size);

    // MERGE HASH TABLE
    ngx_int_t rc;
    rc = ngx_hash_init(&pconf->domain_map_init, pconf->domain_map_keys.keys.elts, pconf->domain_map_keys.keys.nelts);
    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "There's a problem initializing hash table in stream context");
        return NGX_CONF_ERROR;
    }

    for (ngx_uint_t i = 0; i < pconf->domain_map_keys.keys.nelts; ++i) {
        ngx_str_t *s = ((ngx_str_t *)pconf->domain_map_keys.keys.elts) + i;
        ngx_uint_t s_key = ngx_hash_key(s->data, s->len);
        u_char *data = (u_char *)ngx_hash_find(&pconf->domain_map, s_key, s->data, s->len);
        if (data == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "A hash key previously in stream context becomes missing?! This should not happen");
            return NGX_CONF_ERROR;
        }
        rc = ngx_hash_add_key(&cconf->domain_map_keys, s, data, 0);
        if (rc != NGX_OK) {
            if (rc == NGX_BUSY) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "There's a problem merging hash table because of duplicate entry");
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "There's a problem merging hash table");
                return NGX_CONF_ERROR;
            }
        }
    }

    cconf->domain_map_init.max_size = cconf->hash_max_size;
    cconf->domain_map_init.bucket_size = ngx_align(cconf->hash_bucket_size, ngx_cacheline_size);
    rc = ngx_hash_init(&cconf->domain_map_init, cconf->domain_map_keys.keys.elts, cconf->domain_map_keys.keys.nelts);
    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "There's a problem initializing hash table in server context");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

ngx_int_t read_minecraft_varint(u_char *buf, u_int *byte_len) {
    ngx_int_t value = 0;
    ngx_int_t bit_pos = 0;
    u_char *byte = buf;
    while (1) {
        value |= (*byte & 0x7F) << bit_pos;
        if ((*byte & 0x80) == 0) {
            break;
        }

        bit_pos += 7;

        if (bit_pos >= 32) {
            return -1;
        }

        ++byte;
    }
    if (byte_len != NULL) {
        *byte_len = byte - buf + 1;
    }
    return value;
}

u_char *parse_packet_length(ngx_stream_session_t *s, ngx_stream_minecraft_forward_module_ctx_t *ctx, u_char *bufpos, u_int *varint_byte_len, ngx_int_t *packet_len) {
    if (varint_byte_len == NULL || packet_len == NULL) {
        return NULL;
    }

    if (ctx->expected_packet_len == 0) {
        *packet_len = read_minecraft_varint(bufpos, varint_byte_len);
        if (*packet_len <= 0) {
            ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0, "Cannot decode varint properly(%d). At this moment, a correct packet with content is expected", *packet_len);
            return NULL;
        }
        ctx->expected_packet_len = *packet_len;

        bufpos += *varint_byte_len;
        ctx->pos = bufpos;
    }

    return bufpos;
}

u_char *parse_string_from_packet(ngx_pool_t *pool, u_char *bufpos, ngx_int_t len) {
    u_char *rs;
    rs = ngx_pcalloc(pool, (len + 1) * sizeof(u_char));
    if (rs == NULL) {
        return NULL;
    }
    ngx_memcpy(rs, bufpos, len);
    rs[len] = '\0';
    return rs;
}

u_char *create_minecraft_varint(ngx_pool_t *pool, ngx_int_t value, u_int *byte_len) {
    if (pool == NULL || value < 0) {
        return NULL;
    }

    u_char *varint = ngx_pcalloc(pool, sizeof(u_char) * 5);
    if (varint == NULL) {
        return NULL;
    }

    ngx_int_t v = value;
    u_int i = 0;
    u_int msb = 0;
    u_int count = 0;

    while (v > 0) {
        i = v & 0x7F;
        msb = i & 0x40;
        msb <<= 1;
        i |= msb;
        varint[count] = (u_char)i;
        v >>= 7;
        ++count;
    }

    if (byte_len != NULL) {
        *byte_len = count;
    }
    return varint;
}

void remove_module_ctx(ngx_stream_session_t *s) {
    ngx_stream_set_ctx(s, NULL, ngx_stream_minecraft_forward_module);
}

/* Assertion of all protocols referring to Minecraft Java since Netty rewrite */
ngx_int_t is_protocol_num_acceptable(ngx_stream_minecraft_forward_module_ctx_t *ctx) {
    switch (ctx->protocol_num) {
        case 765: // 1.20.3  1.20.4
        case 764: // 1.20.2
        case 763: // 1.20    1.20.1
        case 762: // 1.19.4
        case 761: // 1.19.3
        case 760: // 1.19.1  1.19.2
        case 759: // 1.19
            return NGX_OK;
        default:
            return NGX_ERROR;
    }
}

static ngx_int_t ngx_stream_minecraft_forward_module_preread(ngx_stream_session_t *s) {
    return ngx_stream_minecraft_forward_module_handshake_preread(s);
}

ngx_int_t ngx_stream_minecraft_forward_module_handshake_preread(ngx_stream_session_t *s) {
    ngx_connection_t *c = s->connection;
    c->log->action = "prereading packet";
    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

    ngx_stream_minecraft_forward_module_srv_conf_t *sconf = ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);
    if (!sconf->enabled) {
        return NGX_DECLINED;
    }
    if (c->buffer == NULL) {
        return NGX_AGAIN;
    }

    ngx_stream_minecraft_forward_module_ctx_t *ctx;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_minecraft_forward_module));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ctx->phase = 0;
        ctx->pos = c->buffer->pos;
        ngx_stream_set_ctx(s, ctx, ngx_stream_minecraft_forward_module);
    }

    if (ctx->phase != 0) {
        return NGX_OK;
    }

    u_char *bufpos = ctx->pos;
    u_char *buflast = c->buffer->last;

    if (buflast - bufpos < 5) {
        return NGX_AGAIN;
    }

    if (ctx->phase == 0 && bufpos[0] == (u_char)'\xFE') { // Legacy ping 0xFE
        goto handshake_preread_failure;
    }

    u_int byte_len = 0;
    ngx_int_t prefix_len = 0;
    bufpos = parse_packet_length(s, ctx, bufpos, &byte_len, &prefix_len);
    if (bufpos == NULL) {
        goto handshake_preread_failure;
    }

    if (buflast - bufpos < ctx->expected_packet_len) {
        return NGX_AGAIN;
    }

    if (bufpos[0] != (u_char)'\0') {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Unexpected packet id (%d), 0x00 is expected", bufpos[0]);
        goto handshake_preread_failure;
    }
    ++bufpos;

    if (ctx->phase == 0) {
        ctx->handshake_len = ctx->expected_packet_len;
        ctx->handshake_varint_byte_len = byte_len;

        ngx_int_t protocol_num = -1;
        protocol_num = read_minecraft_varint(bufpos, &byte_len);
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "Protocol number: %d", protocol_num);
        ctx->protocol_num = protocol_num;
        if (is_protocol_num_acceptable(ctx) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0, "Protocol number %d is not acceptable", protocol_num);
            goto handshake_preread_failure;
        }
        bufpos += byte_len;

        prefix_len = read_minecraft_varint(bufpos, &byte_len);
        if (prefix_len <= 0) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "There's a problem getting host string length (%d)", prefix_len);
            goto handshake_preread_failure;
        }
        bufpos += byte_len;

        u_char *hostname_str = parse_string_from_packet(c->pool, bufpos, prefix_len);
        if (hostname_str == NULL) {
            goto handshake_preread_failure;
        }
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "Remote host: %s", hostname_str);
        ctx->remote_hostname = hostname_str;
        ctx->remote_hostname_len = prefix_len;
        bufpos += prefix_len;

        ctx->remote_port |= (bufpos[0] << 8);
        ctx->remote_port |= bufpos[1];

        bufpos += sizeof(u_short); /* Port */

        if (bufpos[0] == (u_char)'\1') {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "Next state: Status");
            ctx->phase = 1;
        } else if (bufpos[0] == (u_char)'\2') {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "Next state: Login");
            ctx->phase = 2;
        } else {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Unknown next state (%d)", bufpos[0]);
            goto handshake_preread_failure;
        }
        ++bufpos;
    } else {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Unknown or wrong phase case (%d) in handshake preread handler", ctx->phase);
        goto handshake_preread_failure;
    }

    ctx->pos = bufpos;
    ctx->expected_packet_len = 0;
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "End of handshake preread");
    return ngx_stream_minecraft_forward_module_loginstart_preread(s);

handshake_preread_failure:
    remove_module_ctx(s);
    return NGX_ERROR;
}

ngx_int_t ngx_stream_minecraft_forward_module_loginstart_preread(ngx_stream_session_t *s) {
    ngx_connection_t *c = s->connection;

    ngx_stream_minecraft_forward_module_ctx_t *ctx;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Contextual data missing in loginstart preread handler! This should not happen");
        goto loginstart_preread_failure;
    }
    if (ctx->phase != 2) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0, "Wrong phase (%d) in loginstart preread handler", ctx->phase);
        goto loginstart_preread_failure;
    }

    u_char *bufpos = ctx->pos;
    u_char *buflast = c->buffer->last;

    if (buflast - bufpos < 5) {
        return NGX_AGAIN;
    }

    u_int byte_len = 0;
    ngx_int_t prefix_len = 0;
    bufpos = parse_packet_length(s, ctx, bufpos, &byte_len, &prefix_len);
    if (bufpos == NULL) {
        goto loginstart_preread_failure;
    }

    if (buflast - bufpos < ctx->expected_packet_len) {
        return NGX_AGAIN;
    }

    if (bufpos[0] != (u_char)'\0') {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Unexpected packet id (%d), 0x00 is expected", bufpos[0]);
        goto loginstart_preread_failure;
    }
    ++bufpos;

    prefix_len = read_minecraft_varint(bufpos, &byte_len);
    if (prefix_len <= 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "There's a problem getting username string length (%d)", prefix_len);
        goto loginstart_preread_failure;
    }
    if (prefix_len > 16) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Username too long (%d)", prefix_len);
        goto loginstart_preread_failure;
    }
    bufpos += byte_len;

    /* Change this later */
    u_char *username_str = parse_string_from_packet(c->pool, bufpos, prefix_len);
    if (username_str == NULL) {
        goto loginstart_preread_failure;
    }
    ngx_log_error(NGX_LOG_INFO, c->log, 0, "Username: %s", username_str);
    ngx_pfree(c->pool, username_str);
    username_str = NULL;
    /* Change this later */
    bufpos += prefix_len;

    if (ctx->protocol_num >= 761) {
        if (ctx->protocol_num <= 763) {
            ++bufpos;
        }
        /* Change this later */
        u_char *uuid = ngx_pcalloc(c->pool, 33 * sizeof(u_char));
        for (int i = 0; i < 32; ++i) {
            if (i % 2) {
                uuid[i] = bufpos[i / 2] & (u_char)0x0F;
            } else {
                uuid[i] = (bufpos[i / 2] & (u_char)0xF0) >> 4;
            }
            if (uuid[i] <= 9) {
                uuid[i] += '0';
            } else if (uuid[i] >= 10 && uuid[i] <= 15) {
                uuid[i] = 'a' + (uuid[i] - 10);
            } else {
                goto loginstart_preread_failure;
            }
        }
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "UUID: %s", uuid);
        ngx_pfree(c->pool, uuid);
        /* Change this later */
        bufpos += 16;
    }

    /* END */
    ctx->pos = NULL;
    ctx->expected_packet_len = 0;
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "End of loginstart preread");
    return NGX_OK;

loginstart_preread_failure:
    remove_module_ctx(s);
    return NGX_ERROR;
}

u_char *get_new_hostname_str(ngx_stream_minecraft_forward_module_srv_conf_t *sconf, u_char *old_str, u_int old_str_len) {
    if (sconf == NULL || old_str == NULL) {
        return NULL;
    }
    ngx_uint_t s_key = ngx_hash_key(old_str, old_str_len);
    u_char *data = ngx_hash_find(&sconf->domain_map, s_key, old_str, old_str_len);
    return data;
}

static ngx_int_t ngx_stream_minecraft_forward_module_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain, ngx_uint_t from_upstream) {
    ngx_connection_t *c = s->connection;
    c->log->action = "filtering and forwarding new login packet";
    if (c->type != SOCK_STREAM || from_upstream || chain == NULL) {
        return ngx_stream_next_filter(s, chain, from_upstream);
    }
    ngx_stream_minecraft_forward_module_ctx_t *ctx;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    if (ctx == NULL) {
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    if (ctx->phase != 2) {
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    u_char *new_hostname_str = NULL;
    u_char *new_hostname_varint_bytes = NULL;
    u_int new_hostname_varint_byte_len = 0;
    ngx_chain_t *chain_point = NULL;
    u_int protocol_varint_byte_len = 0;
    u_char *protocol_num_varint = create_minecraft_varint(c->pool, ctx->protocol_num, &protocol_varint_byte_len);
    if (protocol_num_varint == NULL) {
        goto filter_failure;
    }
    u_int new_hostname_str_len = 0;

    new_hostname_str = get_new_hostname_str(ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module), ctx->remote_hostname, ctx->remote_hostname_len);
    if (new_hostname_str == NULL) {
        new_hostname_str = ctx->remote_hostname;
    }
    new_hostname_str_len = ngx_strlen(new_hostname_str);
    ngx_log_error(NGX_LOG_INFO, c->log, 0, "New hostname string: %s", new_hostname_str);
    new_hostname_varint_bytes = create_minecraft_varint(c->pool, new_hostname_str_len, &new_hostname_varint_byte_len);
    if (new_hostname_str_len <= 0 || new_hostname_varint_bytes == NULL) {
        goto filter_failure;
    }

    // https://wiki.vg/Protocol#Handshake
    // Packet id, Protocol Version varint, Prefixed string (Length varint + content), Server port, Next state.
    u_int new_handshake_len = 1 + protocol_varint_byte_len + new_hostname_varint_byte_len + new_hostname_str_len + sizeof(u_short) + 1;

    // The whole packet is prefixed by a total length in varint.
    u_int new_handshake_varint_byte_len;
    u_char *new_handshake_varint_byte = create_minecraft_varint(c->pool, new_handshake_len, &new_handshake_varint_byte_len);

    u_int old_handshake_len = ctx->handshake_varint_byte_len + ctx->handshake_len;
    new_handshake_len = new_handshake_varint_byte_len + new_handshake_len;

    ngx_chain_t *ln, *out, **ll, *append;

    u_int in_buf_len;
    ngx_int_t last = 0;
    u_int gathered_len = 0;
    for (ln = chain; ln != NULL; ln = ln->next) {
        in_buf_len = ngx_buf_size(ln->buf);
        gathered_len += in_buf_len;
        if (ln->buf->last_buf || ln->buf->last_in_chain) {
            last = 1;
        }
        if (gathered_len >= old_handshake_len) {
            chain_point = ln;
            break;
        }
    }
    if (last) {
        if (gathered_len < old_handshake_len) {
            goto filter_failure;
        }
    }

    u_int split_remnant_len = gathered_len - old_handshake_len;

    ngx_chain_t *new_chain = ngx_chain_get_free_buf(c->pool, &ctx->filter_free);
    if (new_chain == NULL) {
        goto filter_failure;
    }
    new_chain->buf->pos = ngx_pcalloc(c->pool, new_handshake_len * sizeof(u_char));
    if (new_chain->buf->pos == NULL) {
        goto filter_failure;
    }
    new_chain->buf->start = new_chain->buf->pos;
    new_chain->buf->last = new_chain->buf->pos;
    new_chain->buf->end = new_chain->buf->start + (new_handshake_len * sizeof(u_char));
    new_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module;
    new_chain->buf->memory = 1;

    new_chain->buf->last = ngx_cpymem(new_chain->buf->pos, new_handshake_varint_byte, new_handshake_varint_byte_len);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, (u_char *)"\0", 1);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, protocol_num_varint, protocol_varint_byte_len);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_hostname_varint_bytes, new_hostname_varint_byte_len);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_hostname_str, new_hostname_str_len);
    u_char p = (ctx->remote_port & 0xFF00) >> 8;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &p, 1);
    p = ctx->remote_port & 0x00FF;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &p, 1);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, (u_char *)"\2", 1);

    ngx_chain_t *split_chain = NULL;
    if (split_remnant_len > 0) {
        split_chain = ngx_chain_get_free_buf(c->pool, &ctx->filter_free);
        if (split_chain == NULL) {
            goto filter_failure;
        }
        split_chain->buf->pos = ngx_pcalloc(c->pool, split_remnant_len * sizeof(u_char));
        if (split_chain->buf->pos == NULL) {
            goto filter_failure;
        }
        split_chain->buf->start = split_chain->buf->pos;
        split_chain->buf->last = split_chain->buf->pos;
        split_chain->buf->end = split_chain->buf->start + (split_remnant_len * sizeof(u_char));
        split_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module;
        split_chain->buf->memory = 1;

        split_chain->buf->last = ngx_cpymem(split_chain->buf->pos, chain_point->buf->last - split_remnant_len, split_remnant_len);
    }

    // https://nginx.org/en/docs/dev/development_guide.html#http_body_buffers_reuse

    ll = &out;

    *ll = new_chain;
    ll = &new_chain->next;
    append = ngx_alloc_chain_link(c->pool);
    if (append == NULL) {
        goto filter_failure;
    }
    if (split_chain != NULL) {
        append->buf = split_chain->buf;
        if (chain_point->next != NULL) {
            *ll = split_chain;
            ll = &split_chain->next;
            append = ngx_alloc_chain_link(c->pool);
            if (append == NULL) {
                goto filter_failure;
            }
            append->buf = chain_point->next->buf;
        }
    }
    *ll = append;
    ll = &append->next;

    *ll = NULL;

    // https://hg.nginx.org/njs/file/77e4b95109d4/nginx/ngx_stream_js_module.c#l585
    // https://mailman.nginx.org/pipermail/nginx-devel/2022-January/6EUIJQXVFHMRZP3L5SJNWPJKQPROWA7U.html

    for (ln = chain; ln != NULL; ln = ln->next) {
        ln->buf->pos = ln->buf->last;
        if (ln == chain_point) {
            break;
        }
    }
    chain_point = NULL;

    ngx_int_t rc;

    rc = ngx_stream_next_filter(s, out, from_upstream);
    ngx_chain_update_chains(c->pool, &ctx->filter_free, &ctx->filter_busy, &out, (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module);

    if (rc == NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "End of Minecraft-forward-module content filter");
        remove_module_ctx(s);
    }
    return rc;

filter_failure:
    remove_module_ctx(s);
    return NGX_ERROR;
}

static ngx_int_t ngx_stream_minecraft_forward_module_post_init(ngx_conf_t *cf) {
    ngx_stream_handler_pt *hp;
    ngx_stream_core_main_conf_t *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    hp = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (hp == NULL) {
        return NGX_ERROR;
    }
    *hp = ngx_stream_minecraft_forward_module_preread;

    ngx_stream_next_filter = ngx_stream_top_filter;
    ngx_stream_top_filter = ngx_stream_minecraft_forward_module_content_filter;

    return NGX_OK;
}
