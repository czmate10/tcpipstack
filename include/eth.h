#pragma once
#include <unistd.h>
#include <stdio.h>
#include "skbuff.h"
#include "tap.h"

#define ETHERNET_MAX_PAYLOAD_SIZE 1520
#define ETHERNET_HEADER_SIZE 14


struct eth_frame
{
	uint8_t mac_dest[6];
	uint8_t mac_source[6];
	uint16_t eth_type;
	uint8_t payload[];
} __attribute__((packed));


static inline struct eth_frame *eth_frame_from_skb(struct sk_buff *buff) {
	return (struct eth_frame *)buff->data;
}

uint16_t eth_read(struct net_dev *dev, struct eth_frame *frame);
int eth_write(uint8_t dest_mac[], uint16_t eth_type, struct sk_buff *buffer);
