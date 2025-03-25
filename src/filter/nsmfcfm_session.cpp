extern "C"
{
#include <ngx_core.h>
#include <ngx_stream.h>
#include "nsmfcfm.h"
}
#include "nsmfcfm_session.hpp"

bool filterCreateSessionContext(ngx_stream_session_t *s) {
    FilterModuleSessionContext  *ctx;

    ctx = filterGetSessionContext(s);
    if (!ctx) {
        ctx = (FilterModuleSessionContext *)ngx_pcalloc(s->connection->pool, sizeof(FilterModuleSessionContext));
        if (!ctx) {
            return false;
        }
        ctx->pool = ngx_create_pool(_NSMFCFM_SESSION_CTX_DEFAULT_POOL_SIZE_, s->connection->log);
        if (!ctx->pool) {
            return false;
        }
        ngx_stream_set_ctx(s, ctx, ngx_stream_minecraft_forward_content_filter_module);
    }

    return true;
}

FilterModuleSessionContext *filterGetSessionContext(ngx_stream_session_t *s) {
    return (FilterModuleSessionContext *)ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_content_filter_module);
}

void filterRemoveSessionContext(ngx_stream_session_t *s) {
    FilterModuleSessionContext  *ctx;

    ctx = filterGetSessionContext(s);

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "ngx_stream_minecraft_forward_content_filter_module: Removing session context");
#endif

    if (ctx) {
        if (ctx->pool) {
            ngx_destroy_pool(ctx->pool);
            ctx->pool = NULL;
        }
        ngx_pfree(s->connection->pool, ctx);
    }

    ngx_stream_set_ctx(s, NULL, ngx_stream_minecraft_forward_content_filter_module);
}
