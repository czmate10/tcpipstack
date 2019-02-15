#pragma once

#include <netinet/in.h>

uint16_t checksum(register uint16_t *ptr, register uint32_t len, register uint32_t sum);
uint16_t tcp_checksum(void *tcp_segment, uint16_t tcp_segment_len, uint32_t source_ip, uint32_t dest_ip);

#define max(x,y) ( \
    { __auto_type __x = (x); __auto_type __y = (y); \
      __x > __y ? __x : __y; })


#define min(x,y) ( \
    { __auto_type __x = (x); __auto_type __y = (y); \
      __x < __y ? __x : __y; })
