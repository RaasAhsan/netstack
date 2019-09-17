#include <stdio.h>
#include <stdint.h>

uint8_t IP_PROTO_ICMP = 1;
uint8_t IP_PROTO_TCP = 6;

struct ipv4_header {
    uint8_t version;
    uint8_t ihl;
    uint8_t dscp;
    uint8_t ecn;
    uint16_t length;
    uint16_t identification;
    uint8_t flags;
    uint8_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint8_t checksum;
    uint32_t source_addr;
    uint32_t dest_addr;
};


struct ip_packet {
    uint8_t header_length;
    uint16_t data_length;
    struct ipv4_header header;
    char* data;
};

char* get_ip_address(int addr) {
    char* ip = (char*) malloc(15 * sizeof(char));
    sprintf(ip, "%d.%d.%d.%d", (addr & 0xff000000) >> 24, (addr & 0xff0000) >> 16, (addr & 0xff00) >> 8, addr & 0xff);
    return ip;
}

void debug_ipv4_header(struct ipv4_header header) {
    printf(
        "version: %d, ihl: %d, dscp: %d, ecn: %d, length: %d, protocol: %d, saddr: %s, daddr: %s\n", 
        header.version, 
        header.ihl, 
        header.dscp, 
        header.ecn, 
        header.length,
        header.protocol,
        get_ip_address(header.source_addr), 
        get_ip_address(header.dest_addr) // TODO: this is a memory leak
    );
}

struct ipv4_header read_ipv4_header(char* buf) {
    uint8_t version = (uint8_t) buf[0] >> 4;
    uint8_t ihl = (uint8_t) buf[0] & 0x0f;
    uint8_t dscp = (uint8_t) buf[1] >> 2;
    uint8_t ecn = (uint8_t) buf[1] & 0x3;
    uint16_t length = (uint16_t) (buf[2] << 8) + buf[3];
    uint16_t identification = (uint16_t) (buf[4] << 8) + buf[5];
    uint8_t flags = (uint8_t) (buf[6] >> 5);
    uint8_t fragment_offset = (uint8_t) (buf[6] & 0x1f) << 8 + buf[7];
    uint8_t ttl = (uint8_t) buf[8];
    uint8_t protocol = (uint8_t) buf[9];
    uint8_t checksum = (uint16_t) (buf[10] << 8) + buf[11];
    uint32_t source_addr = (uint32_t) (buf[12] << 24) + (buf[13] << 16) + (buf[14] << 8) + buf[15];
    uint32_t dest_addr = (uint32_t) (buf[16] << 24) + (buf[17] << 16) + (buf[18] << 8) + buf[19];
    
    struct ipv4_header header = {version, ihl, dscp, ecn, length, identification, flags, fragment_offset, ttl, protocol, checksum, source_addr, dest_addr};
    return header;
}
