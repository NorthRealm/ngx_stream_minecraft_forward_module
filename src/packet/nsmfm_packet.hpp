#ifndef _NSMFM_MINECRAFT_PACKET_
#define _NSMFM_MINECRAFT_PACKET_

extern "C"
{
#include <ngx_core.h>
#include <ngx_string.h>
}
#include "nsmfm_varint.hpp"

#define _MC_PORT_LEN_ sizeof(u_short)
#define _MC_LONG_LEN_ sizeof(long)

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

    ngx_int_t determineLength(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
    ngx_int_t determineContent(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
};

class MinecraftPacket {
public:
    ngx_pool_t       *pool;
    MinecraftVarint  *id;
    /* Modern Minecraft packet is prefixed by a varint indicating length of Packet ID + Actual payload */
    MinecraftVarint  *length;
    u_char           *payload;

    MinecraftPacket(int id, ngx_pool_t *pool) {
        this->length = MinecraftVarint::create(0);
        this->id = MinecraftVarint::create(id);
        this->pool = pool;
        this->payload = NULL;
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
        if (pool && payload) {
            ngx_pfree(pool, payload);
            payload = NULL;
        }
    }

    ngx_int_t determineLength(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
    ngx_int_t determinePayload(ngx_stream_session_t *s, u_char *bufpos, u_char *buflast);
};

class MinecraftHandshake : public MinecraftPacket {
public:
    MinecraftVarint  *protocolNumber;
    MinecraftString  *serverAddress;
    u_short           serverPort;
    MinecraftVarint  *nextState;

    MinecraftHandshake(ngx_pool_t *pool) : MinecraftPacket(_MC_HANDSHAKE_PACKET_ID_, pool) {
        this->protocolNumber = NULL;
        this->serverAddress = NULL;
        this->nextState = NULL;
        this->serverPort = 0;
    }

    ~MinecraftHandshake() {
        if (protocolNumber) {
            delete protocolNumber;
            protocolNumber = nullptr;
        }
        if (serverAddress) {
            delete serverAddress;
            serverAddress = nullptr;
        }
        if (nextState) {
            delete nextState;
            nextState = nullptr;
        }
    }

    static ngx_int_t determinePayload(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
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

    static ngx_int_t determinePayload(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
};

#endif
