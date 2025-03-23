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
    PrereadModuleHandler   handler;
    bool                   pass;
    bool                   fail;

    MinecraftHandshake    *handshake;
    MinecraftLoginstart   *loginstart;

    u_char                *bufpos;

    ngx_pool_t            *pool;
} PrereadModuleSessionContext;

bool prereadCreateSessionContext(ngx_stream_session_t *s);
PrereadModuleSessionContext *prereadGetSessionContext(ngx_stream_session_t *s);
void prereadRemoveSessionContext(ngx_stream_session_t *s);

#endif
