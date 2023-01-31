#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "parse.h"
void usage() {
    printf("syntax: airodump <interface> \n");
    printf("sample: airodump mon0 \n");
}

int main(int argc, char* argv[]){

    if (argc < 3) {
            usage();
            return -1;
    }
    if(argc == 3)
        Parse(BROADCAST,argv);
    else if(argc ==4)
        Parse(UNICAST,argv);
    else
        Parse(AUTH,argv);
}
