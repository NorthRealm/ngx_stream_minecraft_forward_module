#ifndef _NSMFM_VARINT_UTILS_
#define _NSMFM_VARINT_UTILS_

extern "C"
{
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
}

#define _MC_VARINT_MAX_BYTE_LEN_ 5

class MinecraftVarint {
public:
    u_char bytes[_MC_VARINT_MAX_BYTE_LEN_];
    /* The varint itself also has a length. */
    int    bytesLength : 3;
    
    static int parse(u_char *buf, int *bytesLength);
    static MinecraftVarint* create(int value);

    MinecraftVarint(u_char *bytes, int bytesLength) {
        if (bytes) {
            ngx_memcpy(this->bytes, bytes, bytesLength);
        }
        this->bytesLength = bytesLength;
    }

    MinecraftVarint() : MinecraftVarint(NULL, 0) {}
};

#endif
