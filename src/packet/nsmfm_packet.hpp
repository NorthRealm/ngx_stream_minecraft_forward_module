#ifndef _NSMFM_MINECRAFT_PACKET_
#define _NSMFM_MINECRAFT_PACKET_

extern "C"
{
#include <ngx_core.h>
#include <ngx_string.h>
}
#include "nsmfm_varint.hpp"

#define _MC_PORT_LEN_ sizeof(u_short)

#define _MC_HANDSHAKE_PACKET_ID_         0x00
#define _MC_HANDSHAKE_STATUS_STATE_      1
#define _MC_HANDSHAKE_LOGINSTART_STATE_  2
#define _MC_HANDSHAKE_TRANSFER_STATE_    3

#define _MC_LOGINSTART_PACKET_ID_  0x00

#define _MC_STATUS_REQUEST_PACKET_ID_   0x00
#define _MC_STATUS_RESPONSE_PACKET_ID_  0x00

class MinecraftString {
public:
    ngx_pool_t       *pool;
    MinecraftVarint  *length;
    u_char           *content;

    MinecraftString(ngx_pool_t *pool) {
        this->length = MinecraftVarint::create(0);
        this->pool = pool;
        this->content = NULL;
    }

    MinecraftString() : MinecraftString(NULL) {}

    ~MinecraftString() {
        delete length;
        length = nullptr;
        if (pool && content) {
            ngx_pfree(pool, content);
            content = NULL;
        }
    }

    ngx_int_t determine_length(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
    ngx_int_t determine_content(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
};

class MinecraftPacket {
public:
    MinecraftVarint  *id;
    MinecraftVarint  *length;
    u_char           *content;
    ngx_pool_t       *pool;

    MinecraftPacket(int id, ngx_pool_t *pool) {
        this->length = MinecraftVarint::create(0);
        this->id = MinecraftVarint::create(id);
        this->pool = pool;
        this->content = NULL;
    }

    MinecraftPacket() : MinecraftPacket(0, NULL) {}

    virtual ~MinecraftPacket() {
        if (length) {
            delete length;
            length = nullptr;
        }
        if (id) {
            delete id;
            id = nullptr;
        }
        if (pool && content) {
            ngx_pfree(pool, content);
            content = NULL;
        }
    }

    ngx_int_t determine_length(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
    ngx_int_t determine_content(ngx_stream_session_t *s, u_char *bufpos, u_char *buflast);
};

class MinecraftHandshake : public MinecraftPacket {
public:
    MinecraftVarint  *protocol_number;
    MinecraftString  *server_address;
    u_short           server_port;
    MinecraftVarint  *next_state;

    MinecraftHandshake(ngx_pool_t *pool) : MinecraftPacket(_MC_HANDSHAKE_PACKET_ID_, pool) {
        this->protocol_number = NULL;
        this->server_address = NULL;
        this->next_state = NULL;
        this->server_port = 0;
    }

    ~MinecraftHandshake() {
        if (protocol_number) {
            delete protocol_number;
            protocol_number = nullptr;
        }
        if (server_address) {
            delete server_address;
            server_address = nullptr;
        }
        if (next_state) {
            delete next_state;
            next_state = nullptr;
        }
    }

    static ngx_int_t determine_content(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
};

class MinecraftLoginstart : public MinecraftPacket {
public:
    MinecraftString  *username;
    MinecraftString  *uuid;

    MinecraftLoginstart(ngx_pool_t *pool) : MinecraftPacket(_MC_LOGINSTART_PACKET_ID_, pool) {
        this->username = NULL;
        this->uuid = NULL;
    }

    ~MinecraftLoginstart() {
        if (username) {
            delete username;
            username = nullptr;
        }
        if (uuid) {
            delete uuid;
            uuid = nullptr;
        }
    }

    static ngx_int_t determine_content(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
};

#endif
