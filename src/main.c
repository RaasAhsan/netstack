#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

int tun_alloc(char* dev) {
    struct ifreq ifr;
    int fd, err;

    if ( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
        perror("Cannot open TUN device.");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
        perror("ERR: Could not ioctl tun");
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

void set_if_up(char* dev) {
    char buffer[50];
    sprintf(buffer, "ip link set dev %s up", dev);
    if (system(buffer) != 0) {
        perror("Failed to set interface up.");
        exit(1);
    }
}

void set_if_address(char* dev, char* cidr) {
    char buffer[50];
    sprintf(buffer, "ip address add dev %s local %s", dev, cidr);
    if (system(buffer) != 0) {
        perror("Failed to set interface address.");
        exit(1);
    }
}

void set_if_route(char* dev, char* cidr) {
    char buffer[50];
    sprintf(buffer, "ip route add dev %s %s", dev, cidr);
    if (system(buffer) != 0) {
        perror("Failed to set interface route.");
        exit(1);
    }
}

int tun_read(int fd, char* buf, int len) {
    return read(fd, buf, len);
}

void print_buffer(char* buffer, uint32_t len) {
    printf("Got length %d:\n", len);
    for (int i = 0; i < len; i ++) {
        printf("%d ", buffer[i]);
    }
    printf("\n");
}







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
