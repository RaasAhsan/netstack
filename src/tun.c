#include <linux/if.h>
#include <linux/if_tun.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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
