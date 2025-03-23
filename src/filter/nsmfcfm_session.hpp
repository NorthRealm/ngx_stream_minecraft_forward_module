#ifndef _NSMFCFM_STREAM_SESSION_CONTEXT_
#define _NSMFCFM_STREAM_SESSION_CONTEXT_

extern "C"
{
#include <ngx_core.h>
#include <ngx_stream.h>
}

#define _NSMFCFM_SESSION_CTX_DEFAULT_POOL_SIZE_ 2048

typedef ngx_int_t (*FilterModuleHandler)(ngx_stream_session_t *s, ngx_chain_t *in);

typedef struct {
    bool          pinged;
    bool          fail;

    ngx_chain_t  *in;
    ngx_chain_t  *out;
    ngx_chain_t  *free_chain;
    ngx_chain_t  *busy_chain;

    ngx_pool_t   *pool;

    FilterModuleHandler  clientContentFilter;
    FilterModuleHandler  upstreamContentFilter;
} FilterModuleSessionContext;

bool filterCreateSessionContext(ngx_stream_session_t *s);
FilterModuleSessionContext *filterGetSessionContext(ngx_stream_session_t *s);
void filterRemoveSessionContext(ngx_stream_session_t *s);

#endif
