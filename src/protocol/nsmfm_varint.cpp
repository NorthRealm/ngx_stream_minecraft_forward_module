#include "nsmfm_varint.hpp"

int MinecraftVarint::parse(u_char *buf, int *bytesLength) {
    if (!buf) {
        return -1;
    }

    int      value;
    int      position;
    u_char   byte;
    u_char  *pos;

    value = 0;
    position = 0;

    pos = buf;

    for (;;) {
        byte = *pos;
        value |= (byte & 0x7F) << position;

        if ((byte & 0x80) == 0) {
            break;
        }

        position += 7;

        if (position >= 32) {
            value = -1;
            break;
        }

        pos++;
    }

    if (value < 0) {
        return -1;
    }

    if (bytesLength) {
        *bytesLength = (int)(pos - buf) + 1;
    }

    return value;
}

MinecraftVarint* MinecraftVarint::create(int num) {
    u_char  buf[_MC_VARINT_MAX_BYTE_LEN_];

    int count = 0;

    for (;;) {
        if ((num & ~0x7F) == 0) {
            buf[count++] = num;
            break;
        }

        buf[count++] = ((num & 0x7F) | 0x80);

        num >>= 7;
    }

    return new MinecraftVarint(buf, count);
}
