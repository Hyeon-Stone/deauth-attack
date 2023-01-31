#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "hdr.h"
void Parse(int make_type, char** argv);
DeauthPacket MakePacket(int make_type, char** arg);
DeauthPacketAuth MakeAuthPacket(char** arg);

enum deauthOption{
    BROADCAST =  10,
    UNICAST = 11,
    UNICAST2 = 12,
    AUTH = 13
};

