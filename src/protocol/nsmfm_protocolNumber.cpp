#include "nsmfm_protocolNumber.hpp"

bool isKnownMinecraftProtocolNumber(int var) {
    switch (var) {
        case MINECRAFT_1_21_4:
        case MINECRAFT_1_21_3:
        case MINECRAFT_1_21_1:
        case MINECRAFT_1_20_6:
        case MINECRAFT_1_20_4:
        case MINECRAFT_1_20_2:
        case MINECRAFT_1_20_1:
        case MINECRAFT_1_19_4:
        case MINECRAFT_1_19_3:
        case MINECRAFT_1_19_2:
        case MINECRAFT_1_19:
        case MINECRAFT_1_18_2:
        case MINECRAFT_1_18_1:
        case MINECRAFT_1_17_1:
        case MINECRAFT_1_17:
        case MINECRAFT_1_16_5:
        case MINECRAFT_1_16_3:
        case MINECRAFT_1_16_2:
        case MINECRAFT_1_16_1:
        case MINECRAFT_1_16:
        case MINECRAFT_1_15_2:
        case MINECRAFT_1_15_1:
        case MINECRAFT_1_15:
        case MINECRAFT_1_14_4:
        case MINECRAFT_1_14_3:
        case MINECRAFT_1_14_2:
        case MINECRAFT_1_14_1:
        case MINECRAFT_1_14:
        case MINECRAFT_1_13_2:
        case MINECRAFT_1_13_1:
        case MINECRAFT_1_13:
        case MINECRAFT_1_12_2:
        case MINECRAFT_1_12_1:
        case MINECRAFT_1_12:
        case MINECRAFT_1_11_2:
        case MINECRAFT_1_11:
        case MINECRAFT_1_10_2:
        case MINECRAFT_1_9_4:
        case MINECRAFT_1_9_2:
        case MINECRAFT_1_9_1:
        case MINECRAFT_1_9:
        case MINECRAFT_1_8_9:
        case MINECRAFT_1_7_10:
        case MINECRAFT_1_7_5:
        case MINECRAFT_1_7_1:
            return true;
        default:
            return false;
    }
}
