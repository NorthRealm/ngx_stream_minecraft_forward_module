extern "C"
{
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_hash.h>
#include <ngx_stream.h>
#include "nsmfcfm.h"
#include "../main/nsmfm.h"
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
    FilterModuleSessionContext  *filterContext;

    filterContext = filterGetSessionContext(s);

    if (!filterContext) {
        return ngx_stream_next_filter(s, chain_in, from_upstream);
    }

    if (!filterContext->clientContentFilter) {
        filterContext->clientContentFilter = clientContentFilter;
    }
    if (!filterContext->upstreamContentFilter) {
        filterContext->upstreamContentFilter = upstreamContentFilter;
    }

    return from_upstream ? filterContext->upstreamContentFilter(s, chain_in) : filterContext->clientContentFilter(s, chain_in);
}

static ngx_int_t upstreamContentFilter(ngx_stream_session_t *s, ngx_chain_t *chain_in) {
    ngx_int_t  rc;

    PrereadModuleSessionContext  *prereadContext;
    FilterModuleSessionContext   *filterContext;

    ngx_connection_t  *c;
    c = s->connection;

    c->log->action = (char *)"filtering packets from upstream";

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Response from upstream");
#endif
    rc = ngx_stream_next_filter(s, chain_in, 1);

    filterContext = filterGetSessionContext(s);
    if (!filterContext) {
        goto end_of_upstream_content_filter;
    }

    if (filterContext->pinged) {
#if (NGX_DEBUG)
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Closing connection because already used for pinging");
#endif
        filterRemoveSessionContext(s);
        prereadRemoveSessionContext(s);
        rc = NGX_ERROR;
        goto end_of_upstream_content_filter;
    }

    prereadContext = prereadGetSessionContext(s);
    if (!prereadContext) {
        goto end_of_upstream_content_filter;
    }

    if (MinecraftVarint::parse(prereadContext->handshake->nextState->bytes, NULL) == _MC_HANDSHAKE_STATUS_STATE_) {
        if (rc == NGX_OK) {
            filterContext->pinged = 1;
        }
    }

end_of_upstream_content_filter:
    return rc;
}

static ngx_int_t clientContentFilter(ngx_stream_session_t *s, ngx_chain_t *chain_in) {
    ngx_connection_t  *c;
    ngx_int_t          rc;

    PrereadModuleSessionContext       *prereadContext;
    FilterModuleSessionContext        *filterContext;
    MinecraftForwardModuleServerConf  *serverConf;

    int               prefixedOldHandshakeLength;
    MinecraftVarint  *oldHandshakeLength = nullptr;
    MinecraftVarint  *newHandshakeLength = nullptr;
    MinecraftString  *newHostname;

    u_char            dummyPortNumberChar;
    int               parsedInt;

    int            count_buf_len = 0;
    ngx_chain_t   *target_chain_node = NULL;
    int            split_remnant_buf_len = 0;
    ngx_chain_t   *split_remnant_chain = NULL;
    ngx_chain_t   *new_chain;
    ngx_chain_t  **link_i;
    ngx_chain_t   *append_i;
    ngx_chain_t   *ln;

    c = s->connection;

    filterContext = filterGetSessionContext(s);
    if (!filterContext) {
        return ngx_stream_next_filter(s, chain_in, 0);
    }

    prereadContext = prereadGetSessionContext(s);

    serverConf = (MinecraftForwardModuleServerConf *)ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Request from client");
#endif
    if (filterContext->pinged) {
        return ngx_stream_next_filter(s, chain_in, 0);
    }

    parsedInt = MinecraftVarint::parse(prereadContext->handshake->nextState->bytes, NULL);

    if (!serverConf->replace_on_ping && parsedInt != _MC_HANDSHAKE_LOGINSTART_STATE_) {
        return ngx_stream_next_filter(s, chain_in, 0);
    }

    switch (parsedInt) {
        case _MC_HANDSHAKE_LOGINSTART_STATE_:
            c->log->action = (char *)"filtering and forwarding new minecraft loginstart packet";
            break;
        case _MC_HANDSHAKE_STATUS_STATE_:
            c->log->action = (char *)"filtering and forwarding minecraft ping packet";
            break;
        default:
            goto filter_failure;
    }

    oldHandshakeLength = prereadContext->handshake->length;
    prefixedOldHandshakeLength = MinecraftVarint::parse(oldHandshakeLength->bytes, NULL) + oldHandshakeLength->bytesLength;

    if (serverConf->replace_on_ping) {
        newHostname = getNewHostname(serverConf,
            prereadContext->handshake->serverAddress->content,
            MinecraftVarint::parse(prereadContext->handshake->serverAddress->length->bytes, NULL));

        if (!newHostname) {
            if (serverConf->disconnect_on_nomatch) {
                ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "Closing connection because of no hostname match");
                goto filter_failure;
            }
            newHostname = prereadContext->handshake->serverAddress;
        }
    } else {
        newHostname = prereadContext->handshake->serverAddress;
    }

    if (MinecraftVarint::parse(newHostname->length->bytes, NULL) <= 0) {
        goto filter_failure;
    }

    // https://minecraft.wiki/w/Java_Edition_protocol#Handshake
    // Packet id, Protocol Version varint, Prefixed string (Length varint + content), Server port, Next state.
    newHandshakeLength = MinecraftVarint::create(
        1 + prereadContext->handshake->protocolNumber->bytesLength + newHostname->length->bytesLength
        + MinecraftVarint::parse(newHostname->length->bytes, NULL) + _MC_PORT_LEN_ + 1);

    for (ln = filterContext->in; ln; ln = ln->next) {
        int in_buf_len = ngx_buf_size(ln->buf);

        if (in_buf_len <= 0) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "negative size of or empty buffer encountered");
            goto filter_failure;
        }

        count_buf_len += in_buf_len;

#if (NGX_DEBUG)
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "count_buf_len: %d", count_buf_len);
#endif

        if (count_buf_len >= prefixedOldHandshakeLength) {
            target_chain_node = ln;
            break;
        }
    }

    if (count_buf_len < prefixedOldHandshakeLength) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                        "Incomplete chain of buffer. Expected %d, gathered %d",
                        prefixedOldHandshakeLength, count_buf_len);
        goto filter_failure;
    }

    split_remnant_buf_len = count_buf_len - prefixedOldHandshakeLength;

    new_chain = ngx_chain_get_free_buf(c->pool, &filterContext->free_chain);
    if (!new_chain) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize new chain to store new handshake");
        goto filter_failure;
    }

    new_chain->buf->pos = (u_char *)ngx_pnalloc(c->pool,
        (MinecraftVarint::parse(newHandshakeLength->bytes, NULL) + newHandshakeLength->bytesLength) * sizeof(u_char));
    if (!new_chain->buf->pos) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize new chain buf space");
        goto filter_failure;
    }

    new_chain->buf->start = new_chain->buf->pos;
    new_chain->buf->last = new_chain->buf->pos;
    new_chain->buf->end = new_chain->buf->start +
        (MinecraftVarint::parse(newHandshakeLength->bytes, NULL) + newHandshakeLength->bytesLength);
    new_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_content_filter_module;
    new_chain->buf->memory = 1;

    new_chain->buf->last = ngx_cpymem(new_chain->buf->last,
        newHandshakeLength->bytes, newHandshakeLength->bytesLength);
    
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last,
        prereadContext->handshake->id->bytes, prereadContext->handshake->id->bytesLength);
    
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last,
        prereadContext->handshake->protocolNumber->bytes, prereadContext->handshake->protocolNumber->bytesLength);
    
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last,
        newHostname->length->bytes, newHostname->length->bytesLength);
    
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last,
        newHostname->content, MinecraftVarint::parse(newHostname->length->bytes, NULL));
    
    dummyPortNumberChar = (prereadContext->handshake->serverPort & 0xFF00) >> 8;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &dummyPortNumberChar, 1);
    dummyPortNumberChar = (prereadContext->handshake->serverPort & 0x00FF);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &dummyPortNumberChar, 1);
    
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last,
        prereadContext->handshake->nextState->bytes, prereadContext->handshake->nextState->bytesLength);

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "split_remnant_buf_len: %d", split_remnant_buf_len);
#endif

    if (split_remnant_buf_len > 0) {
        split_remnant_chain = ngx_chain_get_free_buf(c->pool, &filterContext->free_chain);
        if (!split_remnant_chain) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize split remnant chain");
            goto filter_failure;
        }

        split_remnant_chain->buf->pos = (u_char *)ngx_pnalloc(c->pool, split_remnant_buf_len * sizeof(u_char));
        if (!split_remnant_chain->buf->pos) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize split remnant new buf space");
            goto filter_failure;
        }

        split_remnant_chain->buf->start = split_remnant_chain->buf->pos;
        split_remnant_chain->buf->last = split_remnant_chain->buf->pos;
        split_remnant_chain->buf->end = split_remnant_chain->buf->start + split_remnant_buf_len;
        split_remnant_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_content_filter_module;
        split_remnant_chain->buf->memory = 1;

        split_remnant_chain->buf->last = ngx_cpymem(split_remnant_chain->buf->pos,
                                                    target_chain_node->buf->last - split_remnant_buf_len,
                                                    split_remnant_buf_len);
    }

#if (NGX_DEBUG)
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "Filter: Provided hostname: %s, "
                  "New hostname string: %s",
                  prereadContext->handshake->serverAddress->content,
                  newHostname->content);
#endif

    // https://nginx.org/en/docs/dev/development_guide.html#http_body_buffers_reuse

    append_i = NULL;
    link_i = &filterContext->out;

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
    // TODO: What to do with this part?
    while (chain_in) {
        ln = chain_in;
        ln->buf->pos = ln->buf->last;
        if (ln == target_chain_node) {
            chain_in = chain_in->next;
            break;
        }
        chain_in = chain_in->next;
    }

    rc = ngx_stream_next_filter(s, filterContext->out, 0);

#if (NGX_DEBUG)
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "pass to next filter after minecraft packet filter, get rc: %d", rc);
#endif

    ngx_chain_update_chains(c->pool,
                            &filterContext->free_chain,
                            &filterContext->busy_chain,
                            &filterContext->out,
                            (ngx_buf_tag_t)&ngx_stream_minecraft_forward_content_filter_module);

    if (MinecraftVarint::parse(prereadContext->handshake->nextState->bytes, NULL) == _MC_HANDSHAKE_STATUS_STATE_) {
        if (serverConf->replace_on_ping) {
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
    if (newHandshakeLength) {
        delete newHandshakeLength;
    }
    
    rc = filterContext->fail ? NGX_ERROR : rc;
    if (filterContext->fail) {
        if (!filterContext->pinged) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "Filter failed");
        }
    }
    filterRemoveSessionContext(s);
    prereadRemoveSessionContext(s);
    return rc;

filter_failure:
    filterContext->fail = 1;
    goto end_of_filter;
}

static ngx_int_t filterModulePostInit(ngx_conf_t *cf) {
    ngx_stream_next_filter = ngx_stream_top_filter;
    ngx_stream_top_filter = filterHandler;
    return NGX_OK;
}
