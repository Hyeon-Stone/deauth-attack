#include <stdint.h>
#pragma pack(push,1)
typedef struct{
    uint8_t reversion;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
}RadioTap;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct{
    uint16_t type;
    uint16_t padding;
    uint8_t des_mac[6];
    uint8_t src_mac[6];
    uint8_t BSSID[6];
    uint16_t seq_num;
}Beacon;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct {
    uint16_t fixed;
}Manage;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct {
    uint16_t algo;
    uint16_t seq;
    uint16_t status;
}ManageAuth;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct{
    RadioTap radiotap;
    Beacon beacon;
    Manage manage;
}DeauthPacket;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct{
    RadioTap radiotap;
    Beacon beacon;
    ManageAuth manage;
}DeauthPacketAuth;
#pragma pack(pop)

