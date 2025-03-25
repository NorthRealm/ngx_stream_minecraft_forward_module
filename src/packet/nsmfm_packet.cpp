extern "C"
{
#include <ngx_core.h>
}
#include "../protocol/nsmfm_protocolNumber.hpp"
#include "nsmfm_packet.hpp"
#include "../protocol/nsmfm_varint.hpp"
#include "../preread/nsmfpm_session.hpp"
#include "../protocol/nsmfm_uuid.hpp"

/*
 Get string length from prefixed varint. Will move `*bufpos`.
 */
ngx_int_t MinecraftString::determineLength(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast) {
    if (!bufpos || !buflast) {
        return NGX_ERROR;
    }
    if (!*bufpos) {
        return NGX_ERROR;
    }

    int parsedInt;
    int varintLength;

    parsedInt = MinecraftVarint::parse(*bufpos, &varintLength);
    if (parsedInt <= 0) {
        if (buflast - *bufpos < _MC_VARINT_MAX_BYTE_LEN_) {
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    this->length->bytesLength = varintLength;
    ngx_memcpy(this->length->bytes, *bufpos, varintLength);

    (*bufpos) += varintLength;

    return NGX_OK;
}

/*
 Get packet content length from prefixed varint. Will move `*bufpos`.
 */
ngx_int_t MinecraftPacket::determineLength(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast) {
    if (!bufpos || !buflast) {
        return NGX_ERROR;
    }
    if (!*bufpos) {
        return NGX_ERROR;
    }

    int parsedInt;
    int varintLength;

    parsedInt = MinecraftVarint::parse(*bufpos, &varintLength);
    if (parsedInt <= 0) {
        if (buflast - *bufpos < _MC_VARINT_MAX_BYTE_LEN_) {
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    this->length->bytesLength = varintLength;
    ngx_memcpy(this->length->bytes, *bufpos, varintLength);

    (*bufpos) += varintLength;

    return NGX_OK;
}

/*
 Parse string content and copy into `*content`. Will move `*bufpos`.
 */
ngx_int_t MinecraftString::determineContent(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast) {
    if (!bufpos || !buflast) {
        return NGX_ERROR;
    }
    if (!*bufpos) {
        return NGX_ERROR;
    }

    int parsedInt;
    ssize_t stringLen;

    parsedInt = MinecraftVarint::parse(this->length->bytes, NULL);
    if (parsedInt < 0) {
        return NGX_ERROR;
    }
    stringLen = (ssize_t)parsedInt;

    if (buflast - *bufpos < stringLen) {
        return NGX_AGAIN;
    }
    
    this->content = (u_char *)ngx_pnalloc(this->pool, (stringLen + 1) * sizeof(u_char));
    if (!this->content) {
        return NGX_ERROR;
    }
    ngx_memcpy(this->content, *bufpos, stringLen);
    this->content[stringLen] = 0;

    (*bufpos) += stringLen;
    
    return NGX_OK;
}

/*
 Locate packet raw binary content and copy into `*content`.
 Will NOT move `*bufpos` so to parse without moving back pointer again.
 */
ngx_int_t MinecraftPacket::determinePayload(ngx_stream_session_t *s, u_char *bufpos, u_char *buflast) {
    if (!bufpos || !buflast) {
        return NGX_ERROR;
    }

    int parsedInt;
    ssize_t packetLength;

    parsedInt = MinecraftVarint::parse(this->length->bytes, NULL);
    if (parsedInt < 0) {
        return NGX_ERROR;
    }
    packetLength = (ssize_t)parsedInt;

    if (buflast - bufpos < packetLength) {
        return NGX_AGAIN;
    }
    
    this->payload = (u_char *)ngx_pnalloc(this->pool, packetLength * sizeof(u_char));
    if (!this->payload) {
        return NGX_ERROR;
    }
    ngx_memcpy(this->payload, bufpos, packetLength);
    
    return NGX_OK;
}

ngx_int_t MinecraftHandshake::determinePayload(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast) {
    MinecraftHandshake           *handshake;
    PrereadModuleSessionContext  *prereadContext;

    ngx_connection_t  *c;
    ngx_int_t          rc;
    
    int                parsedInt;
    int                varintLength;

    c = s->connection;

    prereadContext = (PrereadModuleSessionContext *)prereadGetSessionContext(s);

    handshake = prereadContext->handshake;

    rc = ((MinecraftPacket *)handshake)->determinePayload(s, *bufpos, buflast);
    if (rc != NGX_OK) {
        return rc;
    }

    parsedInt = MinecraftVarint::parse(handshake->id->bytes, &varintLength);
    if (parsedInt < 0 || *bufpos[0] != parsedInt) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read packet id");
        return NGX_ERROR;
    }
    if (parsedInt != _MC_HANDSHAKE_PACKET_ID_) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "Read unexpected packet id (%d), (%d) is expected",
                      parsedInt, _MC_HANDSHAKE_PACKET_ID_);
        return NGX_ERROR;
    }
    (*bufpos) += varintLength;
    prereadContext->bufpos = *bufpos;

    parsedInt = MinecraftVarint::parse(*bufpos, &varintLength);
    if (parsedInt < 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read protocol number");
        return NGX_ERROR;
    }

    handshake->protocolNumber = MinecraftVarint::create(parsedInt);
    if (!handshake->protocolNumber) {
        return NGX_ERROR;
    }
    if (!isKnownMinecraftProtocolNumber(parsedInt)) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "read varint, unknown protocol number: %d", parsedInt);
        return NGX_ERROR;
    }

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "read varint, protocol number: %d", parsedInt);
#endif

    (*bufpos) += varintLength;
    prereadContext->bufpos = *bufpos;

    handshake->serverAddress = new MinecraftString(prereadContext->pool);
    if (!handshake->serverAddress) {
        return NGX_ERROR;
    }
    rc = handshake->serverAddress->determineLength(s, bufpos, buflast);
    if (rc != NGX_OK) {
cannot_read_server_address_string:
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read hostname");
        return NGX_ERROR;
    }
    rc = handshake->serverAddress->determineContent(s, bufpos, buflast);
    if (rc != NGX_OK) {
        goto cannot_read_server_address_string;
    }

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "read hostname: %s", handshake->serverAddress->content);
#endif

    prereadContext->bufpos = *bufpos;

    handshake->serverPort |= (prereadContext->bufpos[0] << 8);
    handshake->serverPort |= prereadContext->bufpos[1];
    (*bufpos) += _MC_PORT_LEN_;

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "read remote port: %d", handshake->serverPort);
#endif

    parsedInt = MinecraftVarint::parse(*bufpos, &varintLength);
    if (parsedInt < 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read next state");
        return NGX_ERROR;
    }
    handshake->nextState = MinecraftVarint::create(parsedInt);
    if (!handshake->nextState) {
        return NGX_ERROR;
    }

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "read varint, next state: %d", parsedInt);
#endif

    (*bufpos) += varintLength;
    prereadContext->bufpos = *bufpos;

    return NGX_OK;
}

ngx_int_t MinecraftLoginstart::determinePayload(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast) {
    MinecraftHandshake   *handshake;
    MinecraftLoginstart  *loginstart;
    MinecraftUUID        *uuid;

    PrereadModuleSessionContext  *prereadContext;

    ngx_connection_t  *c;
    ngx_int_t          rc;
    
    int                parsedInt;
    int                varintLength;

    c = s->connection;

    prereadContext = (PrereadModuleSessionContext *)prereadGetSessionContext(s);

    handshake = prereadContext->handshake;
    loginstart = prereadContext->loginstart;

    rc = ((MinecraftPacket *)loginstart)->determinePayload(s, *bufpos, buflast);
    if (rc != NGX_OK) {
        return rc;
    }

    parsedInt = MinecraftVarint::parse(loginstart->id->bytes, &varintLength);
    if (parsedInt < 0 || *bufpos[0] != parsedInt) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read packet id");
        return NGX_ERROR;
    }
    if (parsedInt != _MC_LOGINSTART_PACKET_ID_) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "Read unexpected packet id (%d), (%d) is expected",
                      parsedInt, _MC_LOGINSTART_PACKET_ID_);
        return NGX_ERROR;
    }
    (*bufpos) += varintLength;
    prereadContext->bufpos = *bufpos;

    loginstart->username = new MinecraftString(prereadContext->pool);
    if (!loginstart->username) {
        return NGX_ERROR;
    }
    rc = loginstart->username->determineLength(s, bufpos, buflast);
    if (rc != NGX_OK) {
cannot_read_username_string:
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read username");
        return NGX_ERROR;
    }
    rc = loginstart->username->determineContent(s, bufpos, buflast);
    if (rc != NGX_OK) {
        goto cannot_read_username_string;
    }

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "read username: %s", loginstart->username->content);
#endif

    prereadContext->bufpos = *bufpos;

    parsedInt = MinecraftVarint::parse(handshake->protocolNumber->bytes, NULL);
    loginstart->uuid = new MinecraftString(prereadContext->pool);
    loginstart->uuid->length = MinecraftVarint::create(_MC_UUID_BYTE_LEN_);

    if (parsedInt >= MINECRAFT_1_19_3) {
        if (parsedInt <= MINECRAFT_1_20_1) {
            if (!(*bufpos[0])) {
                (*bufpos)++;
                delete loginstart->uuid;
                loginstart->uuid = nullptr;
#if (NGX_DEBUG)
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "No uuid provided");
#endif
                goto end_of_loginstart;
            }
            (*bufpos)++;
        }
        rc = loginstart->uuid->determineContent(s, bufpos, buflast);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read uuid");
            return NGX_ERROR;
        }

        uuid = MinecraftUUID::create(loginstart->uuid->content);
#if (NGX_DEBUG)
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "read uuid: %s", uuid->literals);
#endif
        delete uuid;
        uuid = nullptr;
    }

end_of_loginstart:
    prereadContext->bufpos = *bufpos;

    return NGX_OK;
}