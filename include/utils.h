#pragma once

#include <netinet/in.h>

uint16_t checksum(register uint16_t *ptr, register uint32_t len, register uint32_t sum);