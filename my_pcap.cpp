#include "my_pcap.h"

void print_mac(uint8_t*mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint8_t*ip) {
    printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(uint16_t port) {
    printf("%u\n", port);
}

uint16_t my_ntohs(uint16_t num) {
    return ((num & 0xff00) >> 8) + ((num & 0xff) << 8);
}

void pcap_start(pcap_t *pcap) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char*data;
        c_packet* packet;
        int res = pcap_next_ex(pcap, &header, &data);
        int loop;
        
        if (!res) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){ 
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        packet = (c_packet*)data;
        
        if(packet->protocol != TCP) {
            puts("ONLY TCP...");
            continue;
        }

        printf("=========================================\n");
        printf("%u bytes captured\n", header->caplen);
        printf("S_MAC : ");
        print_mac(packet->s_mac);
        printf("D_MAC : ");
        print_mac(packet->d_mac);
        printf("S_IP : ");
        print_ip(packet->s_ip);
        printf("D_IP : ");
        print_ip(packet->d_ip);
        printf("S_PORT : ");
        print_port(my_ntohs(packet->s_port));
        printf("D_PORT : ");
        print_port(my_ntohs(packet->d_port));
        packet->size = my_ntohs(packet->size);
        packet->size += 0xe;
        if(packet->size - HEADER_SIZE == 0) {
            puts("This Packet don't have data");
            continue;
        }

        else {
            printf("data : [ ");
            loop = (packet->size - HEADER_SIZE > 8) ? 8 : packet->size - HEADER_SIZE;
            for(int i = 0; i < loop; ++i) printf("%X ", packet->data[i]);
            puts("]");
        }
    }
}