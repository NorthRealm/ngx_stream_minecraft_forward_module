#ifndef _NSMFM_UUID_UTILS_
#define _NSMFM_UUID_UTILS_

extern "C"
{
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
}

#define _MC_UUID_LITERAL_NO_DASH_LEN_ 32
#define _MC_UUID_BYTE_LEN_ (_MC_UUID_LITERAL_NO_DASH_LEN_ / 2)

/* Without dashes */
class MinecraftUUID {
public:
    u_char literals[_MC_UUID_LITERAL_NO_DASH_LEN_ + 1];
    
    static MinecraftUUID* create(u_char *buf);
};

#endif