#pragma once

#include "skbuff.h"
#include "eth.h"
#include "ipv4.h"


struct icmp_v4_packet {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint8_t data[];
} __attribute__((packed));


int icmp_process_packet(struct net_dev *dev, struct eth_frame *frame);


static inline struct icmp_v4_packet *icmp_v4_packet_from_skb(struct sk_buff *buff) {
	return (struct icmp_v4_packet *)(buff->data + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE);
}