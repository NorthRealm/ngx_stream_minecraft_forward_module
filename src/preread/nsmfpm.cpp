extern "C"
{
#include <ngx_core.h>
#include <ngx_stream.h>
#include "../main/nsmfm.h"
}
#include "../filter/nsmfcfm_session.hpp"
#include "../protocol/nsmfm_protocolNumber.hpp"
#include "nsmfpm_session.hpp"
#include "../packet/nsmfm_packet.hpp"
#include "../protocol/nsmfm_varint.hpp"

static ngx_int_t prereadModulePostInit(ngx_conf_t *cf);

static ngx_int_t prereadModulePacketHandler(ngx_stream_session_t *s);
static ngx_int_t prereadModuleHandshakePacketHandler(ngx_stream_session_t *s);
static ngx_int_t prereadModuleLoginstartPacketHandler(ngx_stream_session_t *s);

static ngx_stream_module_t nsmfpm_conf_ctx = {
    NULL,  /* preconfiguration */
    prereadModulePostInit, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL  /* merge server configuration */
};

ngx_module_t ngx_stream_minecraft_forward_preread_module = {
    NGX_MODULE_V1,
    &nsmfpm_conf_ctx,      /* module conf context */
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

static ngx_int_t prereadModulePacketHandler(ngx_stream_session_t *s) {
    MinecraftForwardModuleServerConf  *sconf;
    PrereadModuleSessionContext       *ctx;

    ngx_connection_t  *c;
    ngx_int_t          rc;

    c = s->connection;

    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

    sconf = (MinecraftForwardModuleServerConf *)ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);
    if (!sconf->enabled) {
        return NGX_DECLINED;
    }

    c->log->action = (char *)"prereading minecraft packet";

    if (!c->buffer) {
        return NGX_AGAIN;
    }

    if (!prereadCreateSessionContext(s)) {
        return NGX_ERROR;
    }
    ctx = prereadGetSessionContext(s);
    if (!ctx->handler) {
        ctx->handler = prereadModuleHandshakePacketHandler;
    }

    if (ctx->pass) {
        rc = NGX_OK;
        goto end_of_preread;
    }

    rc = ctx->handler(s);

    if (rc == NGX_ERROR) {
        goto preread_failure;
    }

end_of_preread:
    if (ctx->fail) {
        prereadRemoveSessionContext(s);
        filterRemoveSessionContext(s);
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Preread failed");
        rc = NGX_ERROR;
    }

    return rc;

preread_failure:
    ctx->fail = 1;
    goto end_of_preread;
}

static ngx_int_t prereadModuleHandshakePacketHandler(ngx_stream_session_t *s) {
    PrereadModuleSessionContext  *prereadContext;
    FilterModuleSessionContext   *filterContext;

    MinecraftHandshake  *handshake;

    ngx_connection_t  *c;
    u_char            *bufpos;
    ngx_int_t          rc;
    ngx_flag_t         hasBufferRemanent;
    
    int                parsedInt;
    int                varintLength;
    
    u_char             dummyPortNumberChar;

    c = s->connection;
    c->log->action = (char *)"prereading minecraft handshake packet";

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Prereading minecraft handshake packet");
#endif

    prereadContext = (PrereadModuleSessionContext *)prereadGetSessionContext(s);
    if (!prereadContext->buf) {
        prereadContext->buf = c->buffer;
    }

    if (!prereadContext->handshake) {
        prereadContext->handshake = new MinecraftHandshake(prereadContext->pool);
        if (!prereadContext->handshake) {
            return NGX_ERROR;
        }
    }
    handshake = prereadContext->handshake;

    bufpos = prereadContext->buf->pos;
    prereadContext->bufpos = bufpos;

    parsedInt = MinecraftVarint::parse(handshake->length->bytes, NULL);
    if (parsedInt < 0) {
        return NGX_ERROR;
    }
    if (parsedInt == 0) {
        rc = handshake->determineLength(s, &bufpos, c->buffer->last);
        if (rc != NGX_OK) {
            return rc;
        }
        
        parsedInt = MinecraftVarint::parse(handshake->length->bytes, NULL);
#if (NGX_DEBUG)
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "read varint, handshake content len: %d", parsedInt);
#endif
        prereadContext->bufpos = bufpos;
    }

    bufpos = prereadContext->bufpos;

    if (!handshake->payload) {
        rc = handshake->determinePayload(s, &bufpos, c->buffer->last);
        if (rc != NGX_OK) {
            return rc;
        }
        prereadContext->bufpos = bufpos;
    }

    bufpos = prereadContext->bufpos;

    switch (MinecraftVarint::parse(handshake->nextState->bytes, &varintLength)) {
        case _MC_HANDSHAKE_STATUS_STATE_:
            prereadContext->handler = NULL;
            prereadContext->pass = 1;

            if (!filterCreateSessionContext(s)) {
                return NGX_ERROR;
            }
            filterContext = filterGetSessionContext(s);

            filterContext->in = ngx_alloc_chain_link(filterContext->pool);

            if (!filterContext->in) {
                return NGX_ERROR;
            }

            parsedInt = handshake->length->bytesLength + MinecraftVarint::parse(handshake->length->bytes, NULL);

            hasBufferRemanent = c->buffer->last - c->buffer->start > (ssize_t)parsedInt;

            varintLength = hasBufferRemanent ? (c->buffer->last - c->buffer->start) : parsedInt;

            filterContext->in->buf = ngx_create_temp_buf(filterContext->pool, varintLength);
            if (!filterContext->in->buf) {
                return NGX_ERROR;
            }

            filterContext->in->buf->last = ngx_cpymem(filterContext->in->buf->last,
                handshake->length->bytes, handshake->length->bytesLength);
            
            filterContext->in->buf->last = ngx_cpymem(filterContext->in->buf->last,
                handshake->id->bytes, handshake->id->bytesLength);
            
            filterContext->in->buf->last = ngx_cpymem(filterContext->in->buf->last,
                handshake->protocolNumber->bytes, handshake->protocolNumber->bytesLength);
            
            filterContext->in->buf->last = ngx_cpymem(filterContext->in->buf->last,
                handshake->serverAddress->length->bytes,
                handshake->serverAddress->length->bytesLength);
            
            filterContext->in->buf->last = ngx_cpymem(filterContext->in->buf->last,
                handshake->serverAddress->content,
                MinecraftVarint::parse(handshake->serverAddress->length->bytes, NULL));
            
            dummyPortNumberChar = (handshake->serverPort & 0xFF00) >> 8;
            filterContext->in->buf->last = ngx_cpymem(filterContext->in->buf->last, &dummyPortNumberChar, 1);
            dummyPortNumberChar = (handshake->serverPort & 0x00FF);
            filterContext->in->buf->last = ngx_cpymem(filterContext->in->buf->last, &dummyPortNumberChar, 1);
            
            filterContext->in->buf->last = ngx_cpymem(filterContext->in->buf->last,
                handshake->nextState->bytes, handshake->nextState->bytesLength);

            if (hasBufferRemanent) {
                filterContext->in->buf->last = ngx_cpymem(filterContext->in->buf->last,
                    c->buffer->start + parsedInt,
                    (c->buffer->last - c->buffer->start) - parsedInt
                );
#if (NGX_DEBUG)
                ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "buf len: %d", ngx_buf_size(filterContext->in->buf));
#endif
            }

            filterContext->in->buf->last_buf = 1;
            filterContext->in->next = NULL;
#if (NGX_DEBUG)
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Finish prereading handshake packet. Next state status.");
#endif
            return NGX_OK;
        case _MC_HANDSHAKE_LOGINSTART_STATE_:
#if (NGX_DEBUG)
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Finish prereading handshake packet. Next state login.");
#endif
            prereadContext->handler = prereadModuleLoginstartPacketHandler;
            prereadContext->bufpos = bufpos;
            break;
        case _MC_HANDSHAKE_TRANSFER_STATE_:
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Transfer state is not accepted");
            return NGX_ERROR;
        default:
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Unknown next state (%d)", *bufpos);
            return NGX_ERROR;
    }

    return NGX_AGAIN;
}

static ngx_int_t prereadModuleLoginstartPacketHandler(ngx_stream_session_t *s) {
    PrereadModuleSessionContext  *prereadContext;
    FilterModuleSessionContext   *filterContext;

    MinecraftHandshake   *handshake;
    MinecraftLoginstart  *loginstart;

    ngx_connection_t  *c;
    u_char            *bufpos;
    ngx_int_t          rc;
    
    int                parsedInt;
    int                varintLength;

    c = s->connection;
    c->log->action = (char *)"prereading minecraft loginstart packet";

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Prereading minecraft loginstart packet");
#endif

    prereadContext = (PrereadModuleSessionContext *)prereadGetSessionContext(s);

    if (!filterCreateSessionContext(s)) {
        return NGX_ERROR;
    }
    filterContext = filterGetSessionContext(s);

    if (!prereadContext->loginstart) {
        prereadContext->loginstart = new MinecraftLoginstart(prereadContext->pool);
        if (!prereadContext->loginstart) {
            return NGX_ERROR;
        }
    }

    handshake = prereadContext->handshake;
    loginstart = prereadContext->loginstart;
    bufpos = prereadContext->bufpos;

    parsedInt = MinecraftVarint::parse(loginstart->length->bytes, &varintLength);
    if (parsedInt < 0) {
        return NGX_ERROR;
    }
    if (parsedInt == 0) {
        rc = loginstart->determineLength(s, &bufpos, c->buffer->last);
        if (rc != NGX_OK) {
            return rc;
        }
        
        parsedInt = MinecraftVarint::parse(loginstart->length->bytes, NULL);
#if (NGX_DEBUG)
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "read varint, loginstart content len: %d", parsedInt);
#endif
        prereadContext->bufpos = bufpos;
    }

    bufpos = prereadContext->bufpos;

    if (!loginstart->payload) {
        rc = loginstart->determinePayload(s, &bufpos, c->buffer->last);
        if (rc != NGX_OK) {
            return rc;
        }
        prereadContext->bufpos = bufpos;
    }

    bufpos = prereadContext->bufpos;

    filterContext->in = ngx_alloc_chain_link(filterContext->pool);
    if (!filterContext->in) {
        return NGX_ERROR;
    }

    parsedInt = handshake->length->bytesLength + MinecraftVarint::parse(handshake->length->bytes, NULL) +
        loginstart->length->bytesLength + MinecraftVarint::parse(loginstart->length->bytes, NULL);

    filterContext->in->buf = ngx_create_temp_buf(filterContext->pool, parsedInt);

    if (!filterContext->in->buf) {
        return NGX_ERROR;
    }

    filterContext->in->buf->last = ngx_cpymem(filterContext->in->buf->pos, c->buffer->pos, parsedInt);

    filterContext->in->buf->last_buf = 1;
    filterContext->in->next = NULL;

    prereadContext->pass = 1;
    return NGX_OK;
}

static ngx_int_t prereadModulePostInit(ngx_conf_t *cf) {
    ngx_stream_handler_pt       *hp;
    ngx_stream_core_main_conf_t *cmcf;

    cmcf = (ngx_stream_core_main_conf_t *)ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    hp = (ngx_stream_handler_pt *)ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (!hp) {
        return NGX_ERROR;
    }
    *hp = prereadModulePacketHandler;

    return NGX_OK;
}
