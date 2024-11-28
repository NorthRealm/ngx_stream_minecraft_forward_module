extern "C"
{
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_hash.h>
#include <ngx_stream.h>
#include "ngx_stream_minecraft_forward_content_filter_module.h"
#include "../main/ngx_stream_minecraft_forward_module.h"
#include "nsmfcfm_session.h"
}
#include "../preread/nsmfpm_session.hpp"
#include "../protocol/nsmfm_varint.hpp"

ngx_stream_filter_pt  ngx_stream_next_filter;

static ngx_str_t *get_new_hostname_str(nsmfm_srv_conf_t *sconf, u_char *buf, size_t len);

static ngx_int_t nsmfm_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain_in, ngx_uint_t from_upstream);
static ngx_int_t nsmfm_client_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain_in);
static ngx_int_t nsmfm_upstream_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain_in);

static ngx_int_t nsmfcfm_post_init(ngx_conf_t *cf);

static ngx_stream_module_t nsmfcfm_conf_ctx = {
    NULL,              /* preconfiguration */
    nsmfcfm_post_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL  /* merge server configuration */
};

ngx_module_t ngx_stream_minecraft_forward_content_filter_module = {
    NGX_MODULE_V1,
    &nsmfcfm_conf_ctx,     /* module conf context */
    NULL,                  /* module directives */
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

static ngx_str_t *get_new_hostname_str(nsmfm_srv_conf_t *sconf, u_char *buf, size_t len) {
    if (sconf == NULL || buf == NULL) {
        return NULL;
    }

    return (ngx_str_t *)ngx_hash_find(&sconf->hostname_map, ngx_hash_key(buf, len), buf, len);
}

static ngx_int_t nsmfm_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain_in, ngx_uint_t from_upstream) {
    if (nsmfcfm_get_session_context(s) == NULL) {
        return ngx_stream_next_filter(s, chain_in, from_upstream);
    }

    if (from_upstream) {
        return nsmfm_upstream_content_filter(s, chain_in);
    } else {
        return nsmfm_client_content_filter(s, chain_in);
    }
}

static ngx_int_t nsmfm_upstream_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain_in) {
    ngx_connection_t         *c;
    ngx_int_t                 rc;

    nsmfpm_session_context   *mctx;
    nsmfcfm_session_context  *cfctx;
    MinecraftHandshake       *old_handshake;

    c = s->connection;

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Response from upstream");
#endif
    rc = ngx_stream_next_filter(s, chain_in, 1);

    cfctx = nsmfcfm_get_session_context(s);
    if (cfctx == NULL) {
        goto end_of_upstream_content_filter;
    }

    if (cfctx->pinged) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "Closing connection because already used for pinging");
        nsmfcfm_remove_session_context(s);
        nsmfpm_remove_session_context(s);
        rc = NGX_ERROR;
        goto end_of_upstream_content_filter;
    }

    mctx = nsmfpm_get_session_context(s);
    if (mctx == NULL) {
        goto end_of_upstream_content_filter;
    }

    old_handshake = mctx->handshake;

    if (MinecraftVarint::parse(old_handshake->next_state->bytes, NULL) == _MC_HANDSHAKE_STATUS_STATE_) {
        if (rc == NGX_OK) {
            cfctx->pinged = true;
        }
    }

end_of_upstream_content_filter:
    return rc;
}

static ngx_int_t nsmfm_client_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain_in) {
    ngx_connection_t         *c;
    ngx_int_t                 rc;
    nsmfpm_session_context   *mctx;
    nsmfcfm_session_context  *cfctx;
    nsmfm_srv_conf_t         *sconf;

    MinecraftHandshake       *old_handshake;
    int                       old_handshake_len; /* This includes varint byte len */
    MinecraftVarint          *new_handshake_content_len;

    MinecraftString          *new_hostname;
    bool                      newnew = false;
    MinecraftVarint           protocol_number;

    ngx_str_t                *str = NULL;
    u_char                    pchar;
    int                       parsed_var;

    int                       in_buf_len;
    int                       gathered_buf_len;
    ngx_chain_t              *target_chain_node;
    int                       split_remnant_len;
    ngx_chain_t              *new_chain;
    ngx_chain_t              *split_remnant_chain;

    ngx_chain_t             **link_i;
    ngx_chain_t              *append_i;

    c = s->connection;
    cfctx = nsmfcfm_get_session_context(s);
    if (cfctx == NULL) {
        return ngx_stream_next_filter(s, chain_in, 0);
    }

    mctx = nsmfpm_get_session_context(s);
    old_handshake = mctx->handshake;

    c->log->action = (char *) "filtering minecraft packet";

    sconf = (nsmfm_srv_conf_t *) ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Request from client");
#endif
    if (cfctx->pinged) {
        return ngx_stream_next_filter(s, chain_in, 0);
    }

    parsed_var = MinecraftVarint::parse(old_handshake->next_state->bytes, NULL);

    if (!sconf->replace_on_ping && parsed_var != _MC_HANDSHAKE_LOGINSTART_STATE_) {
        return ngx_stream_next_filter(s, chain_in, 0);
    }

    if (cfctx->out) {
        goto chain_update;
    }

    switch (parsed_var) {
        case _MC_HANDSHAKE_LOGINSTART_STATE_:
            c->log->action = (char *) "filtering and forwarding new minecraft loginstart packet";
            break;
        case _MC_HANDSHAKE_STATUS_STATE_:
            c->log->action = (char *) "filtering and forwarding minecraft ping packet";
            break;
        default:
            c->log->action = (char *) "filtering minecraft packet";
            goto filter_failure;
    }

    protocol_number = *old_handshake->protocol_number;

    if (sconf->replace_on_ping) {
        str = get_new_hostname_str(sconf,
            old_handshake->server_address->content,
            MinecraftVarint::parse(old_handshake->server_address->length->bytes, NULL));
        if (str == NULL) {
            if (sconf->disconnect_on_nomatch) {
                ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "Closing connection because of no hostname match");
                goto filter_failure;
            }
            new_hostname = old_handshake->server_address;
        } else {
            new_hostname = new MinecraftString();
            new_hostname->length = MinecraftVarint::create(str->len);
            new_hostname->content = str->data;
            new_hostname->pool = NULL;
            newnew = true;
        }
    } else {
        new_hostname = old_handshake->server_address;
    }

    if (MinecraftVarint::parse(new_hostname->length->bytes, NULL) <= 0) {
        goto filter_failure;
    }

    // https://wiki.vg/Protocol#Handshake
    // Packet id, Protocol Version varint, Prefixed string (Length varint + content), Server port, Next state.
    parsed_var = 1 + protocol_number.bytes_length + new_hostname->length->bytes_length
        + MinecraftVarint::parse(new_hostname->length->bytes, NULL) + _MC_PORT_LEN_ + 1;
        new_handshake_content_len = MinecraftVarint::create(parsed_var);

    old_handshake_len = mctx->handshake->length->bytes_length + MinecraftVarint::parse(mctx->handshake->length->bytes, NULL);

#if (NGX_DEBUG)
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                  "old_handshake_len (including varint): %d, "
                  "new_handshake_len (content): %d",
                  old_handshake_len,
                  parsed_var);
#endif

    target_chain_node = NULL;

    in_buf_len = 0;
    gathered_buf_len = 0;

    for (ngx_chain_t *ln = cfctx->in; ln != NULL; ln = ln->next) {
        in_buf_len = ngx_buf_size(ln->buf);

        if (in_buf_len <= 0) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "negative size of or empty buffer encountered");
            goto filter_failure;
        }

        gathered_buf_len += in_buf_len;
        if (ln->buf->last_buf) {
            if (gathered_buf_len < old_handshake_len) {
                ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                              "Incomplete chain of buffer. Expected %d, gathered %d",
                              old_handshake_len, gathered_buf_len);
                goto filter_failure;
            }
        }

#if (NGX_DEBUG)
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "gathered_buf_len: %d", gathered_buf_len);
#endif

        if (gathered_buf_len >= old_handshake_len) {
            target_chain_node = ln;
            break;
        }
    }

    split_remnant_len = gathered_buf_len - old_handshake_len;
    split_remnant_chain = NULL;

    new_chain = ngx_chain_get_free_buf(c->pool, &cfctx->free_chain);
    if (new_chain == NULL) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize new chain to store new handshake");
        goto filter_failure;
    }

    new_chain->buf->pos = (u_char *) ngx_pnalloc(c->pool,
        (MinecraftVarint::parse(new_handshake_content_len->bytes, NULL)
        + new_handshake_content_len->bytes_length) * sizeof(u_char));
    if (new_chain->buf->pos == NULL) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize new chain buf space");
        goto filter_failure;
    }

    new_chain->buf->start = new_chain->buf->pos;
    new_chain->buf->last = new_chain->buf->pos;
    new_chain->buf->end = new_chain->buf->start + (MinecraftVarint::parse(new_handshake_content_len->bytes, NULL)
        + new_handshake_content_len->bytes_length);
    new_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_content_filter_module;
    new_chain->buf->memory = 1;

    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_handshake_content_len->bytes, new_handshake_content_len->bytes_length);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, mctx->handshake->id->bytes, mctx->handshake->id->bytes_length);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, protocol_number.bytes, protocol_number.bytes_length);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_hostname->length->bytes, new_hostname->length->bytes_length);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_hostname->content, MinecraftVarint::parse(new_hostname->length->bytes, NULL));
    pchar = (old_handshake->server_port & 0xFF00) >> 8;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &pchar, 1);
    pchar = (old_handshake->server_port & 0x00FF);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &pchar, 1);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, old_handshake->next_state->bytes, old_handshake->next_state->bytes_length);

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "split_remnant_len: %d", split_remnant_len);
#endif

    if (split_remnant_len > 0) {
        split_remnant_chain = ngx_chain_get_free_buf(c->pool, &cfctx->free_chain);
        if (split_remnant_chain == NULL) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize split remnant chain");
            goto filter_failure;
        }

        split_remnant_chain->buf->pos = (u_char *) ngx_pnalloc(c->pool, split_remnant_len * sizeof(u_char));
        if (split_remnant_chain->buf->pos == NULL) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize split remnant new buf space");
            goto filter_failure;
        }

        split_remnant_chain->buf->start = split_remnant_chain->buf->pos;
        split_remnant_chain->buf->last = split_remnant_chain->buf->pos;
        split_remnant_chain->buf->end = split_remnant_chain->buf->start + split_remnant_len;
        split_remnant_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_content_filter_module;
        split_remnant_chain->buf->memory = 1;

        split_remnant_chain->buf->last = ngx_cpymem(split_remnant_chain->buf->pos,
                                                    target_chain_node->buf->last - split_remnant_len,
                                                    split_remnant_len);
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "Filter: Provided hostname: %s, "
                  "New hostname string: %s",
                  old_handshake->server_address->content,
                  new_hostname->content);

    // https://nginx.org/en/docs/dev/development_guide.html#http_body_buffers_reuse

    append_i = NULL;
    link_i = &cfctx->out;

    *link_i = new_chain;
    link_i = &new_chain->next;

    append_i = ngx_alloc_chain_link(c->pool);
    if (append_i == NULL) {
        goto filter_failure;
    }
    append_i->buf = NULL;
    append_i->next = NULL;

    if (split_remnant_chain != NULL) {
        if (target_chain_node->next != NULL) {
            *link_i = split_remnant_chain;
            link_i = &split_remnant_chain->next;

            append_i->buf = target_chain_node->next->buf;
            append_i->next = target_chain_node->next->next;
        } else {
            append_i->buf = split_remnant_chain->buf;
            append_i->next = split_remnant_chain->next;
        }
    } else if (target_chain_node->next != NULL) {
        append_i->buf = target_chain_node->next->buf;
        append_i->next = target_chain_node->next->next;
    }

    if (append_i->buf != NULL) {
        *link_i = append_i;
        link_i = &append_i->next;
    }

    // https://hg.nginx.org/njs/file/77e4b95109d4/nginx/ngx_stream_js_module.c#l585
    // https://mailman.nginx.org/pipermail/nginx-devel/2022-January/6EUIJQXVFHMRZP3L5SJNWPJKQPROWA7U.html

    for (ngx_chain_t *ln = chain_in; ln != NULL; ln = ln->next) {
        ln->buf->pos = ln->buf->last;
        if (ln == target_chain_node) {
            break;
        }
    }

chain_update:
    rc = ngx_stream_next_filter(s, cfctx->out, 0);

#if (NGX_DEBUG)
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "pass to next filter after minecraft packet filter, get rc: %d", rc);
#endif

    ngx_chain_update_chains(c->pool,
                            &cfctx->free_chain,
                            &cfctx->busy_chain,
                            &cfctx->out,
                            (ngx_buf_tag_t)&ngx_stream_minecraft_forward_content_filter_module);

    if (MinecraftVarint::parse(old_handshake->next_state->bytes, NULL) == _MC_HANDSHAKE_STATUS_STATE_) {
        if (sconf->replace_on_ping) {
            switch (rc) {
                case NGX_OK:
                    goto end_of_filter;
                case NGX_AGAIN:
                    return rc;
                case NGX_ERROR:
                default:
                    goto filter_failure;
            }
        } else {
            goto filter_failure;
        }
    }

end_of_filter:
    if (newnew) {
        delete new_hostname;
    }
    
    rc = cfctx->fail ? NGX_ERROR : rc;
    if (cfctx->fail) {
        if (!cfctx->pinged) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "Filter failed");
        }
    }
    nsmfcfm_remove_session_context(s);
    nsmfpm_remove_session_context(s);
    return rc;

filter_failure:
    cfctx->fail = true;
    goto end_of_filter;
}

static ngx_int_t nsmfcfm_post_init(ngx_conf_t *cf) {
    ngx_stream_next_filter = ngx_stream_top_filter;
    ngx_stream_top_filter = nsmfm_content_filter;
    return NGX_OK;
}