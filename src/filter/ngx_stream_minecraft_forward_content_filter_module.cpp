extern "C"
{
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_hash.h>
#include <ngx_stream.h>
#include "ngx_stream_minecraft_forward_content_filter_module.h"
#include "../main/ngx_stream_minecraft_forward_module.h"
}
#include "nsmfcfm_session.hpp"
#include "../preread/nsmfpm_session.hpp"
#include "../protocol/nsmfm_varint.hpp"

ngx_stream_filter_pt  ngx_stream_next_filter;

static MinecraftString *getNewHostname(MinecraftForwardModuleServerConf *sconf, u_char *buf, size_t len);

static ngx_int_t filterHandler(ngx_stream_session_t *s, ngx_chain_t *chain_in, ngx_uint_t from_upstream);
static ngx_int_t clientContentFilter(ngx_stream_session_t *s, ngx_chain_t *chain_in);
static ngx_int_t upstreamContentFilter(ngx_stream_session_t *s, ngx_chain_t *chain_in);

static ngx_int_t filterModulePostInit(ngx_conf_t *cf);

static ngx_stream_module_t nsmfcfm_conf_ctx = {
    NULL,              /* preconfiguration */
    filterModulePostInit, /* postconfiguration */

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

static MinecraftString *getNewHostname(MinecraftForwardModuleServerConf *sconf, u_char *buf, size_t len) {
    if (!sconf || !buf) {
        return NULL;
    }

    u_char           *res;
    MinecraftString  *r;
    
    res = (u_char *)ngx_hash_find(&sconf->hostnames, ngx_hash_key(buf, len), buf, len);
    if (!res) {
        return NULL;
    }

    r = new MinecraftString();
    r->length = MinecraftVarint::create(ngx_strlen(res));
    r->content = res;
    return r;
}

static ngx_int_t filterHandler(ngx_stream_session_t *s, ngx_chain_t *chain_in, ngx_uint_t from_upstream) {
    FilterModuleSessionContext  *cfctx;

    cfctx = filterGetSessionContext(s);

    if (!cfctx) {
        return ngx_stream_next_filter(s, chain_in, from_upstream);
    }

    if (!cfctx->clientContentFilter) {
        cfctx->clientContentFilter = clientContentFilter;
    }
    if (!cfctx->upstreamContentFilter) {
        cfctx->upstreamContentFilter = upstreamContentFilter;
    }

    return from_upstream ? cfctx->upstreamContentFilter(s, chain_in) : cfctx->clientContentFilter(s, chain_in);
}

static ngx_int_t upstreamContentFilter(ngx_stream_session_t *s, ngx_chain_t *chain_in) {
    ngx_connection_t  *c;
    ngx_int_t          rc;

    PrereadModuleSessionContext  *mctx;
    FilterModuleSessionContext   *cfctx;

    c = s->connection;

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Response from upstream");
#endif
    rc = ngx_stream_next_filter(s, chain_in, 1);

    cfctx = filterGetSessionContext(s);
    if (!cfctx) {
        goto end_of_upstream_content_filter;
    }

    if (cfctx->pinged) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "Closing connection because already used for pinging");
        filterRemoveSessionContext(s);
        prereadRemoveSessionContext(s);
        rc = NGX_ERROR;
        goto end_of_upstream_content_filter;
    }

    mctx = prereadGetSessionContext(s);
    if (!mctx) {
        goto end_of_upstream_content_filter;
    }

    if (MinecraftVarint::parse(mctx->handshake->next_state->bytes, NULL) == _MC_HANDSHAKE_STATUS_STATE_) {
        if (rc == NGX_OK) {
            cfctx->pinged = true;
        }
    }

end_of_upstream_content_filter:
    return rc;
}

static ngx_int_t clientContentFilter(ngx_stream_session_t *s, ngx_chain_t *chain_in) {
    ngx_connection_t  *c;
    ngx_int_t          rc;

    PrereadModuleSessionContext       *mctx;
    FilterModuleSessionContext        *cfctx;
    MinecraftForwardModuleServerConf  *sconf;

    u_char            port_char;
    int               parsed_var;
    int               old_len;
    MinecraftVarint  *old_content_len = nullptr;
    MinecraftVarint  *new_content_len = nullptr;
    MinecraftString  *new_hostname;

    int            in_buf_len;
    int            gathered_buf_len;
    ngx_chain_t   *target_chain_node;
    int            split_remnant_len;
    ngx_chain_t   *new_chain;
    ngx_chain_t   *split_remnant_chain;
    ngx_chain_t  **link_i;
    ngx_chain_t   *append_i;

    ngx_chain_t   *ln;

    c = s->connection;

    cfctx = filterGetSessionContext(s);
    if (!cfctx) {
        return ngx_stream_next_filter(s, chain_in, 0);
    }

    mctx = prereadGetSessionContext(s);

    sconf = (MinecraftForwardModuleServerConf *)ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Request from client");
#endif
    if (cfctx->pinged) {
        return ngx_stream_next_filter(s, chain_in, 0);
    }

    parsed_var = MinecraftVarint::parse(mctx->handshake->next_state->bytes, NULL);

    if (!sconf->replace_on_ping && parsed_var != _MC_HANDSHAKE_LOGINSTART_STATE_) {
        return ngx_stream_next_filter(s, chain_in, 0);
    }

    switch (parsed_var) {
        case _MC_HANDSHAKE_LOGINSTART_STATE_:
            c->log->action = (char *)"filtering and forwarding new minecraft loginstart packet";
            break;
        case _MC_HANDSHAKE_STATUS_STATE_:
            c->log->action = (char *)"filtering and forwarding minecraft ping packet";
            break;
        default:
            goto filter_failure;
    }

    old_content_len = mctx->handshake->length;
    old_len = MinecraftVarint::parse(old_content_len->bytes, NULL) + old_content_len->bytesLength;

    if (sconf->replace_on_ping) {
        new_hostname = getNewHostname(sconf,
            mctx->handshake->server_address->content,
            MinecraftVarint::parse(mctx->handshake->server_address->length->bytes, NULL));
        if (!new_hostname) {
            if (sconf->disconnect_on_nomatch) {
                ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "Closing connection because of no hostname match");
                goto filter_failure;
            }
            new_hostname = mctx->handshake->server_address;
        }
    } else {
        new_hostname = mctx->handshake->server_address;
    }

    if (MinecraftVarint::parse(new_hostname->length->bytes, NULL) <= 0) {
        goto filter_failure;
    }

    // https://minecraft.wiki/w/Java_Edition_protocol#Handshake
    // Packet id, Protocol Version varint, Prefixed string (Length varint + content), Server port, Next state.
    parsed_var = 1 + mctx->handshake->protocol_number->bytesLength + new_hostname->length->bytesLength
        + MinecraftVarint::parse(new_hostname->length->bytes, NULL) + _MC_PORT_LEN_ + 1;

    new_content_len = MinecraftVarint::create(parsed_var);

    target_chain_node = NULL;

    in_buf_len = 0;
    gathered_buf_len = 0;

    for (ln = cfctx->in; ln; ln = ln->next) {
        in_buf_len = ngx_buf_size(ln->buf);

        if (in_buf_len <= 0) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "negative size of or empty buffer encountered");
            goto filter_failure;
        }

        gathered_buf_len += in_buf_len;
        if (ln->buf->last_buf) {
            if (gathered_buf_len < old_len) {
                ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                              "Incomplete chain of buffer. Expected %d, gathered %d",
                              old_len, gathered_buf_len);
                goto filter_failure;
            }
        }

#if (NGX_DEBUG)
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "gathered_buf_len: %d", gathered_buf_len);
#endif

        if (gathered_buf_len >= old_len) {
            target_chain_node = ln;
            break;
        }
    }

    split_remnant_len = gathered_buf_len - old_len;
    split_remnant_chain = NULL;

    new_chain = ngx_chain_get_free_buf(c->pool, &cfctx->free_chain);
    if (!new_chain) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize new chain to store new handshake");
        goto filter_failure;
    }

    new_chain->buf->pos = (u_char *)ngx_pnalloc(c->pool,
        (MinecraftVarint::parse(new_content_len->bytes, NULL) + new_content_len->bytesLength) * sizeof(u_char));
    if (!new_chain->buf->pos) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize new chain buf space");
        goto filter_failure;
    }

    new_chain->buf->start = new_chain->buf->pos;
    new_chain->buf->last = new_chain->buf->pos;
    new_chain->buf->end = new_chain->buf->start +
        (MinecraftVarint::parse(new_content_len->bytes, NULL) + new_content_len->bytesLength);
    new_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_content_filter_module;
    new_chain->buf->memory = 1;

    new_chain->buf->last = ngx_cpymem(new_chain->buf->last,
        new_content_len->bytes, new_content_len->bytesLength);
    
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last,
        mctx->handshake->id->bytes, mctx->handshake->id->bytesLength);
    
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last,
        mctx->handshake->protocol_number->bytes, mctx->handshake->protocol_number->bytesLength);
    
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last,
        new_hostname->length->bytes, new_hostname->length->bytesLength);
    
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last,
        new_hostname->content, MinecraftVarint::parse(new_hostname->length->bytes, NULL));
    
    port_char = (mctx->handshake->server_port & 0xFF00) >> 8;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &port_char, 1);
    port_char = (mctx->handshake->server_port & 0x00FF);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &port_char, 1);
    
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last,
        mctx->handshake->next_state->bytes, mctx->handshake->next_state->bytesLength);

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "split_remnant_len: %d", split_remnant_len);
#endif

    if (split_remnant_len > 0) {
        split_remnant_chain = ngx_chain_get_free_buf(c->pool, &cfctx->free_chain);
        if (!split_remnant_chain) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize split remnant chain");
            goto filter_failure;
        }

        split_remnant_chain->buf->pos = (u_char *)ngx_pnalloc(c->pool, split_remnant_len * sizeof(u_char));
        if (!split_remnant_chain->buf->pos) {
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
                  mctx->handshake->server_address->content,
                  new_hostname->content);

    // https://nginx.org/en/docs/dev/development_guide.html#http_body_buffers_reuse

    append_i = NULL;
    link_i = &cfctx->out;

    *link_i = new_chain;
    link_i = &new_chain->next;

    append_i = ngx_alloc_chain_link(c->pool);
    if (!append_i) {
        goto filter_failure;
    }
    append_i->buf = NULL;
    append_i->next = NULL;

    if (split_remnant_chain) {
        if (target_chain_node->next) {
            *link_i = split_remnant_chain;
            link_i = &split_remnant_chain->next;

            append_i->buf = target_chain_node->next->buf;
            append_i->next = target_chain_node->next->next;
        } else {
            append_i->buf = split_remnant_chain->buf;
            append_i->next = split_remnant_chain->next;
        }
    } else if (target_chain_node->next) {
        append_i->buf = target_chain_node->next->buf;
        append_i->next = target_chain_node->next->next;
    }

    if (append_i->buf) {
        *link_i = append_i;
        link_i = &append_i->next;
    }

    // https://hg.nginx.org/njs/file/77e4b95109d4/nginx/ngx_stream_js_module.c#l585
    // https://mailman.nginx.org/pipermail/nginx-devel/2022-January/6EUIJQXVFHMRZP3L5SJNWPJKQPROWA7U.html

    while (chain_in) {
        ln = chain_in;
        ln->buf->pos = ln->buf->last;
        if (ln == target_chain_node) {
            chain_in = chain_in->next;
            break;
        }
        chain_in = chain_in->next;
    }

    rc = ngx_stream_next_filter(s, cfctx->out, 0);

#if (NGX_DEBUG)
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "pass to next filter after minecraft packet filter, get rc: %d", rc);
#endif

    ngx_chain_update_chains(c->pool,
                            &cfctx->free_chain,
                            &cfctx->busy_chain,
                            &cfctx->out,
                            (ngx_buf_tag_t)&ngx_stream_minecraft_forward_content_filter_module);

    if (MinecraftVarint::parse(mctx->handshake->next_state->bytes, NULL) == _MC_HANDSHAKE_STATUS_STATE_) {
        if (sconf->replace_on_ping) {
            switch (rc) {
                case NGX_OK:
                    goto end_of_filter;
                default:
                    goto filter_failure;
            }
        } else {
            goto filter_failure;
        }
    }

end_of_filter:
    if (new_content_len) {
        delete new_content_len;
    }
    
    rc = cfctx->fail ? NGX_ERROR : rc;
    if (cfctx->fail) {
        if (!cfctx->pinged) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "Filter failed");
        }
    }
    filterRemoveSessionContext(s);
    prereadRemoveSessionContext(s);
    return rc;

filter_failure:
    cfctx->fail = true;
    goto end_of_filter;
}

static ngx_int_t filterModulePostInit(ngx_conf_t *cf) {
    ngx_stream_next_filter = ngx_stream_top_filter;
    ngx_stream_top_filter = filterHandler;
    return NGX_OK;
}
