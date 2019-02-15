#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "tap.h"


int tap_alloc(char *dev) {
	struct ifreq ifr = {0};
	int fd, err;

	if((fd = open("/dev/net/tun", O_RDWR)) == -1) {
		perror("cannot open /dev/net/tun");
		return -1;
	}

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *
	 *        IFF_NO_PI - Do not provide packet information
	 */
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if(*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if(ioctl(fd, TUNSETIFF, (void *) &ifr) < 0){
		close(fd);
		perror("ioctl failed");
		return -1;
	}

	strcpy(dev, ifr.ifr_name);
	return fd;
}

void tap_get_mac(int dev_fd, uint8_t *hwaddr) {
	struct ifreq ifr = {};
	ioctl(dev_fd, SIOCGIFHWADDR, &ifr);
	memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
}


struct net_dev *tap_init_dev(char *dev) {
	int sock_fd = tap_alloc(dev);
	if(sock_fd < 0)
		return NULL;

	// file descriptor
	device = malloc(sizeof(struct net_dev));
	if(device == NULL) {
		perror("could not allocate memory for TAP device");
		exit(1);
	}

	device->sock_fd = sock_fd;
	device->mtu = TAP_DEVICE_MTU;
	tap_get_mac(sock_fd, device->hwaddr);

	// IPv4 address
	inet_pton(AF_INET, TAP_DEVICE_IP, &device->ipv4);

	return device;
}

void free_tap_device() {
	close(device->sock_fd);
	free(device);
}

struct net_dev *get_tap_device() {
	return device;
}