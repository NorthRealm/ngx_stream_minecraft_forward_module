extern "C"
{
#include <ngx_core.h>
#include "../protocol/nsmfm_protocol_number.h"
}
#include "nsmfm_packet.hpp"
#include "../protocol/nsmfm_varint.hpp"
#include "../preread/nsmfpm_session.hpp"
#include "../protocol/nsmfm_uuid.hpp"

/*
 Get string length from prefixed varint. Will move `*bufpos`.
 */
ngx_int_t MinecraftString::determine_length(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast) {
    if (bufpos == NULL || buflast == NULL) {
        return NGX_ERROR;
    }
    if (*bufpos == NULL) {
        return NGX_ERROR;
    }

    int var;
    int varint_bytes_length;

    var = MinecraftVarint::parse(*bufpos, &varint_bytes_length);
    if (var <= 0) {
        if (buflast - *bufpos < _MC_VARINT_MAX_BYTE_LEN_) {
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    this->length->bytes_length = varint_bytes_length;
    ngx_memcpy(this->length->bytes, *bufpos, varint_bytes_length);

    (*bufpos) += varint_bytes_length;

    return NGX_OK;
}

/*
 Get packet content length from prefixed varint. Will move `*bufpos`.
 */
ngx_int_t MinecraftPacket::determine_length(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast) {
    if (bufpos == NULL || buflast == NULL) {
        return NGX_ERROR;
    }
    if (*bufpos == NULL) {
        return NGX_ERROR;
    }

    int var;
    int varint_bytes_length;

    var = MinecraftVarint::parse(*bufpos, &varint_bytes_length);
    if (var <= 0) {
        if (buflast - *bufpos < _MC_VARINT_MAX_BYTE_LEN_) {
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    this->length->bytes_length = varint_bytes_length;
    ngx_memcpy(this->length->bytes, *bufpos, varint_bytes_length);

    (*bufpos) += varint_bytes_length;

    return NGX_OK;
}

/*
 Parse string content and copy into `*content`. Will move `*bufpos`.
 */
ngx_int_t MinecraftString::determine_content(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast) {
    if (bufpos == NULL || buflast == NULL) {
        return NGX_ERROR;
    }
    if (*bufpos == NULL) {
        return NGX_ERROR;
    }

    ssize_t str_length = MinecraftVarint::parse(this->length->bytes, NULL);
    if (str_length < 0) {
        return NGX_ERROR;
    }

    if (buflast - *bufpos < str_length) {
        return NGX_AGAIN;
    }
    
    this->content = (u_char *) ngx_pnalloc(this->pool, str_length + 1);
    if (!this->content) {
        return NGX_ERROR;
    }
    ngx_memcpy(this->content, *bufpos, str_length);
    this->content[str_length] = 0;

    (*bufpos) += str_length;
    
    return NGX_OK;
}

/*
 Locate packet raw binary content and copy into `*content`.
 Will NOT move `*bufpos` so to parse without moving back pointer again.
 */
ngx_int_t MinecraftPacket::determine_content(ngx_stream_session_t *s, u_char *bufpos, u_char *buflast) {
    if (bufpos == NULL || buflast == NULL) {
        return NGX_ERROR;
    }
    
    ssize_t packet_length = MinecraftVarint::parse(this->length->bytes, NULL);
    if (packet_length < 0) {
        return NGX_ERROR;
    }

    if (buflast - bufpos < packet_length) {
        return NGX_AGAIN;
    }
    
    this->content = (u_char *) ngx_pnalloc(this->pool, packet_length);
    if (!this->content) {
        return NGX_ERROR;
    }
    ngx_memcpy(this->content, bufpos, packet_length);

    
    return NGX_OK;
}

ngx_int_t MinecraftHandshake::determine_content(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast) {
    ngx_connection_t         *c;
    
    nsmfpm_session_context   *ctx;

    ngx_int_t                 rc;
    int                       parse_var;
    int                       varint_byte_len;

    MinecraftHandshake       *handshake;

    c = s->connection;

    ctx = (nsmfpm_session_context *) nsmfpm_get_session_context(s);

    handshake = ctx->handshake;

    rc = ((MinecraftPacket *)handshake)->determine_content(s, *bufpos, buflast);
    if (rc != NGX_OK) {
        return rc;
    }

    parse_var = MinecraftVarint::parse(handshake->id->bytes, &varint_byte_len);
    if (parse_var < 0 || *bufpos[0] != parse_var) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read packet id");
        return NGX_ERROR;
    }
    if (parse_var != _MC_HANDSHAKE_PACKET_ID_) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "Read unexpected packet id (%d), (%d) is expected",
                      parse_var, _MC_HANDSHAKE_PACKET_ID_);
        return NGX_ERROR;
    }
    (*bufpos) += varint_byte_len;
    ctx->bufpos = *bufpos;

    parse_var = MinecraftVarint::parse(*bufpos, &varint_byte_len);
    if (parse_var < 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read protocol number");
        return NGX_ERROR;
    }

    handshake->protocol_number = MinecraftVarint::create(parse_var);
    if (!handshake->protocol_number) {
        return NGX_ERROR;
    }
    if (!nsmfm_is_known_protocol(parse_var)) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "read varint, unknown protocol number: %d", parse_var);
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read varint, protocol number: %d", parse_var);
    (*bufpos) += varint_byte_len;
    ctx->bufpos = *bufpos;

    handshake->server_address = new MinecraftString(ctx->pool);
    if (!handshake->server_address) {
        return NGX_ERROR;
    }
    rc = handshake->server_address->determine_length(s, bufpos, buflast);
    if (rc != NGX_OK) {
cannot_read_server_address_string:
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read hostname");
        return NGX_ERROR;
    }
    rc = handshake->server_address->determine_content(s, bufpos, buflast);
    if (rc != NGX_OK) {
        goto cannot_read_server_address_string;
    }
    
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read hostname: %s", handshake->server_address->content);

    ctx->bufpos = *bufpos;

    handshake->server_port |= (ctx->bufpos[0] << 8);
    handshake->server_port |= ctx->bufpos[1];
    (*bufpos) += _MC_PORT_LEN_;
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read remote port: %d", handshake->server_port);

    parse_var = MinecraftVarint::parse(*bufpos, &varint_byte_len);
    if (parse_var < 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read next state");
        return NGX_ERROR;
    }
    handshake->next_state = MinecraftVarint::create(parse_var);
    if (!handshake->next_state) {
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read varint, next state: %d", parse_var);

    (*bufpos) += varint_byte_len;
    ctx->bufpos = *bufpos;

    return NGX_OK;
}

ngx_int_t MinecraftLoginstart::determine_content(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast) {
    ngx_connection_t         *c;
    
    nsmfpm_session_context   *ctx;

    ngx_int_t                 rc;
    int                       parse_var;
    int                       varint_byte_len;

    MinecraftHandshake       *handshake;
    MinecraftLoginstart      *loginstart;

    MinecraftUUID            *uuid;

    c = s->connection;

    ctx = (nsmfpm_session_context *) nsmfpm_get_session_context(s);

    handshake = ctx->handshake;
    loginstart = ctx->loginstart;

    rc = ((MinecraftPacket *)loginstart)->determine_content(s, *bufpos, buflast);
    if (rc != NGX_OK) {
        return rc;
    }

    parse_var = MinecraftVarint::parse(loginstart->id->bytes, &varint_byte_len);
    if (parse_var < 0 || *bufpos[0] != parse_var) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read packet id");
        return NGX_ERROR;
    }
    if (parse_var != _MC_LOGINSTART_PACKET_ID_) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "Read unexpected packet id (%d), (%d) is expected",
                      parse_var, _MC_LOGINSTART_PACKET_ID_);
        return NGX_ERROR;
    }
    (*bufpos) += varint_byte_len;
    ctx->bufpos = *bufpos;

    loginstart->username = new MinecraftString(ctx->pool);
    if (!loginstart->username) {
        return NGX_ERROR;
    }
    rc = loginstart->username->determine_length(s, bufpos, buflast);
    if (rc != NGX_OK) {
cannot_read_username_string:
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read username");
        return NGX_ERROR;
    }
    rc = loginstart->username->determine_content(s, bufpos, buflast);
    if (rc != NGX_OK) {
        goto cannot_read_username_string;
    }
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read username: %s", loginstart->username->content);

    ctx->bufpos = *bufpos;

    parse_var = MinecraftVarint::parse(handshake->protocol_number->bytes, NULL);
    loginstart->uuid = new MinecraftString(ctx->pool);
    loginstart->uuid->length = MinecraftVarint::create(_MC_UUID_BYTE_LEN_);
    if (parse_var >= MINECRAFT_1_19_3) {
        if (parse_var <= MINECRAFT_1_20_1) {
            if (!(*bufpos[0])) {
                (*bufpos)++;
                delete loginstart->uuid;
                loginstart->uuid = nullptr;
                goto end_of_loginstart;
            }
            (*bufpos)++;
        }
        rc = loginstart->uuid->determine_content(s, bufpos, buflast);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read uuid");
            return NGX_ERROR;
        }

        uuid = MinecraftUUID::create(loginstart->uuid->content);

        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read uuid: %s", uuid->literals);

        delete uuid;
        uuid = nullptr;
    }

end_of_loginstart:
    ctx->bufpos = *bufpos;

    return NGX_OK;
}