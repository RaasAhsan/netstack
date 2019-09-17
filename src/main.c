
#include "tun.c"
#include "ipv4.c"


#include <stdio.h>
#include <errno.h>

#include <stdint.h>

void print_buffer(char* buffer, uint32_t len) {
    printf("Got length %d:\n", len);
    for (int i = 0; i < len; i ++) {
        printf("%d ", buffer[i]);
    }
    printf("\n");
}







void handle_icmp_packet(struct ip_packet packet) {
    
}

void handle_ip_packet(struct ip_packet packet) {
    if (packet.header.protocol == IP_PROTO_ICMP) {
        handle_icmp_packet(packet);
    }
}

int main() {
    char* dev = (char*) malloc(10);
    int fd = tun_alloc(dev);

    set_if_up(dev);
    set_if_route(dev, "10.8.0.0/24");
    set_if_address(dev, "10.8.0.1");

    printf("fd: %d, dev: %s\n", fd, dev);

    while (1) {
        printf("---- NEW PACKET ----\n");
        char buffer[65536]; // max size is total length, in a 16-bit field
        int len = tun_read(fd, buffer, 65536);

        uint8_t version = (uint8_t) (buffer[0] & 0xf0) >> 4;
        if (version != 4) {
            printf("Received ipv6 header. skipping\n");
            continue;
        }

        struct ipv4_header header = read_ipv4_header(buffer);

        uint8_t header_length = header.ihl * 4;
        uint16_t data_length = header.length - header_length;

        char* data = (char*) malloc(sizeof(char) * data_length);
        data = memcpy(data, buffer + header_length, data_length);

        struct ip_packet packet = { header_length, data_length, header, data }; // memory leak if packet outlives data
        handle_ip_packet(packet);

        printf("\n");
    }
    
    return 0;
}
