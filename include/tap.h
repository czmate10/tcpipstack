#pragma once

#include <stdint.h>


struct netdev {
	uint32_t sock_fd;
	uint8_t hwaddr[6];
	uint32_t ipv4;
	uint64_t ipv6[2];
};

int tap_alloc(char *dev);
struct netdev *init_tap_device(char *dev);
void free_tap_device();
struct netdev *get_tap_device();