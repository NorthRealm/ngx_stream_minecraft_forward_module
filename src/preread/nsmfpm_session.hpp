#ifndef _NSMFPM_STREAM_SESSION_CONTEXT_
#define _NSMFPM_STREAM_SESSION_CONTEXT_

#include "../packet/nsmfm_packet.hpp"

extern "C"
{
#include <ngx_core.h>
#include <ngx_stream.h>
}

#define _NSMFPM_SESSION_CTX_DEFAULT_POOL_SIZE_ 2048

typedef ngx_int_t (*PrereadModuleHandler)(ngx_stream_session_t *s);

typedef struct {
    /* Handler function for prereading handshake and loginstart */
    PrereadModuleHandler   handler;
    /* Preread passes */
    ngx_flag_t             pass;
    /* Preread failure */
    ngx_flag_t             fail;

    /* Handshake packet derived from prereading */
    MinecraftHandshake    *handshake;
    /* Loginstart packet derived from prereading */
    MinecraftLoginstart   *loginstart;

    ngx_buf_t             *buf;
    u_char                *bufpos;
    ngx_pool_t            *pool;
} PrereadModuleSessionContext;

bool prereadCreateSessionContext(ngx_stream_session_t *s);
PrereadModuleSessionContext *prereadGetSessionContext(ngx_stream_session_t *s);
void prereadRemoveSessionContext(ngx_stream_session_t *s);

#endif
