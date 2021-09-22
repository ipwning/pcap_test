#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

#define HEADER_SIZE 54
#define TCP 6

typedef struct {
    uint8_t d_mac[6];
    uint8_t s_mac[6];
    uint16_t type;
    uint8_t pad1[2];
    uint16_t size;
    uint16_t id;
    uint8_t pad2[2];
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t s_ip[4];
    uint8_t d_ip[4];
    uint16_t s_port;
    uint16_t d_port;
    uint8_t pad3[10];
    uint16_t win_size;
    uint16_t checksum;
    uint16_t urgent;
    uint8_t data[];
}c_packet; // custom packet structure

typedef struct {
    char* dev_;
} Param;

void pcap_start(pcap_t *pcap);