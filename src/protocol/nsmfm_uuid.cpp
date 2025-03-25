#include "nsmfm_uuid.hpp"

MinecraftUUID* MinecraftUUID::create(u_char *buf) {
    MinecraftUUID  *res;
    u_char          uuid[_MC_UUID_LITERAL_NO_DASH_LEN_ + 1];

    for (int i = 0; i < _MC_UUID_LITERAL_NO_DASH_LEN_; ++i) {
        uuid[i] = i % 2 ? (buf[i / 2] & (u_char)0x0F) : ((buf[i / 2] & (u_char)0xF0) >> 4);

        if (uuid[i] <= 9) {
            uuid[i] += '0';
        } else if (uuid[i] >= 10 && uuid[i] <= 15) {
            uuid[i] = 'a' + (uuid[i] - 10);
        } else {
            return nullptr;
        }
    }
    uuid[_MC_UUID_LITERAL_NO_DASH_LEN_] = 0;

    res = new MinecraftUUID();
    ngx_memcpy(res->literals, uuid, _MC_UUID_LITERAL_NO_DASH_LEN_ + 1);

    return res;
}
