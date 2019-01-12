#pragma once

#include <netinet/in.h>

uint16_t checksum(register uint16_t *ptr, register uint32_t len, register uint32_t sum);

#define max(x,y) ( \
    { __auto_type __x = (x); __auto_type __y = (y); \
      __x > __y ? __x : __y; })


#define min(x,y) ( \
    { __auto_type __x = (x); __auto_type __y = (y); \
      __x < __y ? __x : __y; })
