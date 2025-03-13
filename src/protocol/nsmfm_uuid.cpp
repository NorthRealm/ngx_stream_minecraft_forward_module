#include "nsmfm_uuid.hpp"

MinecraftUUID* MinecraftUUID::create(u_char *bufpos) {
    MinecraftUUID  *res;
    u_char          uuid[_MC_UUID_LITERAL_LEN_ + 1];

    for (int i = 0; i < _MC_UUID_LITERAL_LEN_; ++i) {
        uuid[i] = i % 2 ? (bufpos[i / 2] & (u_char)0x0F) : ((bufpos[i / 2] & (u_char)0xF0) >> 4);

        if (uuid[i] <= 9) {
            uuid[i] += '0';
        } else if (uuid[i] >= 10 && uuid[i] <= 15) {
            uuid[i] = 'a' + (uuid[i] - 10);
        } else {
            return nullptr;
        }
    }
    uuid[_MC_UUID_LITERAL_LEN_] = 0;

    res = new MinecraftUUID();
    ngx_memcpy(res->literals, uuid, _MC_UUID_LITERAL_LEN_ + 1);

    return res;
}
