#pragma once

#include <stdint.h>

#define TAP_DEVICE_MAC "00:50:56:f1:c4:10"
#define TAP_DEVICE_IP "192.168.100.6"
#define TAP_DEVICE_MTU 1500


struct net_dev {
	int sock_fd;
	uint8_t hwaddr[6];
	uint32_t ipv4;
	uint64_t ipv6[2];
	uint16_t mtu;
};

struct net_dev *device;

int tap_alloc(char *dev);
struct net_dev *init_tap_device(char *dev);
void free_tap_device();
struct net_dev *get_tap_device();