#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "tap.h"


int tap_alloc(char *dev)
{
	struct ifreq ifr;
	int fd, err;

	if((fd = open("/dev/net/tun", O_RDWR)) == -1) {
		perror("cannot open /dev/net/tun");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

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


struct netdev *init_tap_device(char *dev) {
	int sock_fd = tap_alloc(dev);
	if(sock_fd < 0)
		return NULL;

	// file descriptor
	device = malloc(sizeof(struct netdev));
	if(device == NULL) {
		perror("could not allocate memory for TAP device");
		exit(1);
	}

	device->sock_fd = sock_fd;

	// HW address
	for(int i = 0; i < 6; i++)
		sscanf(&TAP_DEVICE_MAC[i*3], "%2hhx", &device->hwaddr[i]);

	// IPv4 address
	inet_pton(AF_INET, TAP_DEVICE_IP, &device->ipv4);

	return device;
}

void free_tap_device() {
	close((int)device->sock_fd);
	free(device);
}

struct netdev *get_tap_device() {
	return device;
}