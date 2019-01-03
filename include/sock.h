#pragma once

#include <stdlib.h>

#include "tap.h"


struct sock {
	uint8_t protocol;  // TCP, UDP?
	struct netdev *dev;

	uint32_t source_ip;
	uint32_t dest_ip;
	uint16_t source_port;
	uint16_t dest_port;
};
