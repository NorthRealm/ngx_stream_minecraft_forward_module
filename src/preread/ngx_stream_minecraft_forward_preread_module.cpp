extern "C"
{
#include <ngx_core.h>
#include <ngx_stream.h>
#include "../main/ngx_stream_minecraft_forward_module.h"
#include "../protocol/nsmfm_protocol_number.h"
#include "../filter/nsmfcfm_session.h"
}
#include "nsmfpm_session.hpp"
#include "../packet/nsmfm_packet.hpp"
#include "../protocol/nsmfm_varint.hpp"

static ngx_int_t nsmfpm_post_init(ngx_conf_t *cf);

static ngx_int_t nsmfpm(ngx_stream_session_t *s);
static ngx_int_t nsmfpm_handshake(ngx_stream_session_t *s);
static ngx_int_t nsmfpm_loginstart(ngx_stream_session_t *s);

static ngx_stream_module_t nsmfpm_conf_ctx = {
    NULL,  /* preconfiguration */
    nsmfpm_post_init, /* postconfiguration */

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

static ngx_int_t nsmfpm(ngx_stream_session_t *s) {
    ngx_connection_t        *c;
    nsmfm_srv_conf_t        *sconf;
    nsmfpm_session_context  *ctx;

    ngx_int_t                rc;

    c = s->connection;

    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

    sconf = (nsmfm_srv_conf_t *) ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);
    if (!sconf->enabled) {
        return NGX_DECLINED;
    }

    c->log->action = (char *) "prereading minecraft packet";

    if (c->buffer == NULL) {
        return NGX_AGAIN;
    }

    ctx = nsmfpm_get_session_context(s);
    if (ctx == NULL) {
        if (!nsmfpm_create_session_context(s)) {
            return NGX_ERROR;
        }
        ctx = nsmfpm_get_session_context(s);
        ctx->handler = nsmfpm_handshake;
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
        nsmfpm_remove_session_context(s);
        nsmfcfm_remove_session_context(s);
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Preread failed");
        rc = NGX_ERROR;
    }

    return rc;

preread_failure:
    ctx->fail = 1;
    goto end_of_preread;
}

static ngx_int_t nsmfpm_handshake(ngx_stream_session_t *s) {
    ngx_connection_t         *c;
    nsmfpm_session_context   *ctx;
    nsmfcfm_session_context  *cfctx;

    u_char                   *bufpos;
    ngx_int_t                 rc;
    int                       parse_var;
    int                       varint_byte_len;
    u_char                    port_char;

    ngx_flag_t                buffer_remanent;

    MinecraftHandshake       *handshake;

    c = s->connection;
    c->log->action = (char *) "prereading minecraft handshake packet";

    ctx = (nsmfpm_session_context *) nsmfpm_get_session_context(s);

    if (!ctx->handshake) {
        ctx->handshake = new MinecraftHandshake(ctx->pool);
        if (!ctx->handshake) {
            return NGX_ERROR;
        }
    }
    handshake = ctx->handshake;

    bufpos = c->buffer->pos;
    ctx->bufpos = bufpos;

    parse_var = MinecraftVarint::parse(handshake->length->bytes, NULL);
    if (parse_var < 0) {
        return NGX_ERROR;
    } else if (parse_var == 0) {
        rc = handshake->determine_length(s, &bufpos, c->buffer->last);
        if (rc != NGX_OK) {
            return rc;
        }
        
        parse_var = MinecraftVarint::parse(handshake->length->bytes, NULL);
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read varint, handshake content len: %d", parse_var);
        ctx->bufpos = bufpos;
    }

    bufpos = ctx->bufpos;

    if (!handshake->content) {
        rc = handshake->determine_content(s, &bufpos, c->buffer->last);
        if (rc != NGX_OK) {
            return rc;
        }
        ctx->bufpos = bufpos;
    }

    bufpos = ctx->bufpos;

    switch (MinecraftVarint::parse(handshake->next_state->bytes, &varint_byte_len)) {
        case _MC_HANDSHAKE_STATUS_STATE_:
            ctx->handler = NULL;
            ctx->pass = true;

            if (!nsmfcfm_create_session_context(s)) {
                return NGX_ERROR;
            }
            cfctx = nsmfcfm_get_session_context(s);

            cfctx->in = ngx_alloc_chain_link(cfctx->pool);

            if (!cfctx->in) {
                return NGX_ERROR;
            }

            parse_var = handshake->length->bytes_length + MinecraftVarint::parse(handshake->length->bytes, NULL);

            buffer_remanent = c->buffer->last - c->buffer->start > (ssize_t)parse_var;

            varint_byte_len = buffer_remanent ? (c->buffer->last - c->buffer->start) : parse_var;

            cfctx->in->buf = ngx_create_temp_buf(cfctx->pool, varint_byte_len);
            if (!cfctx->in->buf) {
                return NGX_ERROR;
            }

            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last,
                handshake->length->bytes, handshake->length->bytes_length);
            
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last,
                handshake->id->bytes, handshake->id->bytes_length);
            
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last,
                handshake->protocol_number->bytes, handshake->protocol_number->bytes_length);
            
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last,
                handshake->server_address->length->bytes,
                handshake->server_address->length->bytes_length);
            
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last,
                handshake->server_address->content,
                MinecraftVarint::parse(handshake->server_address->length->bytes, NULL));
            
            port_char = (handshake->server_port & 0xFF00) >> 8;
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last, &port_char, 1);
            port_char = (handshake->server_port & 0x00FF);
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last, &port_char, 1);
            
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last,
                handshake->next_state->bytes, handshake->next_state->bytes_length);

            if (buffer_remanent) {
                cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last,
                    c->buffer->start + parse_var,
                    (c->buffer->last - c->buffer->start) - parse_var
                );
#if (NGX_DEBUG)
                ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "buf len: %d", ngx_buf_size(cfctx->in->buf));
#endif
            }

            cfctx->in->buf->last_buf = 1;
            cfctx->in->next = NULL;

            return NGX_OK;
        case _MC_HANDSHAKE_LOGINSTART_STATE_:
            ctx->handler = nsmfpm_loginstart;
            ctx->bufpos = bufpos;
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

static ngx_int_t nsmfpm_loginstart(ngx_stream_session_t *s) {
    ngx_connection_t         *c;
    nsmfpm_session_context   *ctx;
    nsmfcfm_session_context  *cfctx;

    u_char                   *bufpos;
    ngx_int_t                 rc;
    int                       parse_var;
    int                       varint_byte_len;

    MinecraftHandshake       *handshake;
    MinecraftLoginstart      *loginstart;

    c = s->connection;
    c->log->action = (char *) "prereading minecraft loginstart packet";

    ctx = (nsmfpm_session_context *) nsmfpm_get_session_context(s);
    if (!nsmfcfm_create_session_context(s)) {
        return NGX_ERROR;
    }
    cfctx = nsmfcfm_get_session_context(s);

    if (!ctx->loginstart) {
        ctx->loginstart = new MinecraftLoginstart(ctx->pool);
        if (!ctx->loginstart) {
            return NGX_ERROR;
        }
    }

    handshake = ctx->handshake;
    loginstart = ctx->loginstart;
    bufpos = ctx->bufpos;

    parse_var = MinecraftVarint::parse(loginstart->length->bytes, &varint_byte_len);
    if (parse_var < 0) {
        return NGX_ERROR;
    }
    if (parse_var == 0) {
        rc = loginstart->determine_length(s, &bufpos, c->buffer->last);
        if (rc != NGX_OK) {
            return rc;
        }
        
        parse_var = MinecraftVarint::parse(loginstart->length->bytes, NULL);
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read varint, loginstart content len: %d", parse_var);
        ctx->bufpos = bufpos;
    }

    bufpos = ctx->bufpos;

    if (!loginstart->content) {
        rc = loginstart->determine_content(s, &bufpos, c->buffer->last);
        if (rc != NGX_OK) {
            return rc;
        }
        ctx->bufpos = bufpos;
    }

    bufpos = ctx->bufpos;

    cfctx->in = ngx_alloc_chain_link(cfctx->pool);
    if (!cfctx->in) {
        return NGX_ERROR;
    }

    parse_var = handshake->length->bytes_length + MinecraftVarint::parse(handshake->length->bytes, NULL) +
        loginstart->length->bytes_length + MinecraftVarint::parse(loginstart->length->bytes, NULL);

    cfctx->in->buf = ngx_create_temp_buf(cfctx->pool, parse_var);

    if (!cfctx->in->buf) {
        return NGX_ERROR;
    }

    cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->pos, c->buffer->pos, parse_var);

    cfctx->in->buf->last_buf = 1;
    cfctx->in->next = NULL;

    ctx->pass = true;
    return NGX_OK;
}

static ngx_int_t nsmfpm_post_init(ngx_conf_t *cf) {
    ngx_stream_handler_pt       *hp;
    ngx_stream_core_main_conf_t *cmcf;

    cmcf = (ngx_stream_core_main_conf_t *) ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    hp = (ngx_stream_handler_pt *) ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (hp == NULL) {
        return NGX_ERROR;
    }
    *hp = nsmfpm;

    return NGX_OK;
}
