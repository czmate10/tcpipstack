#pragma once

#include <stdint.h>
#include <netinet/in.h>

#include "skbuff.h"
#include "sock.h"
#include "tap.h"
#include "eth.h"


#define IP_HEADER_SIZE 20
#define IP_DEFAULT_TTL 64

#define IP_FLAG_DF 0x4000  // don't fragment
#define IP_FLAG_MF 0x2000  // more fragments


struct ipv4_packet {
	uint8_t header_len:4, version:4;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t fragment_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t source_ip;
	uint32_t dest_ip;
	uint8_t data[];
} __attribute__((packed));

static inline struct ipv4_packet *ipv4_packet_from_skb(struct sk_buff *buff) {
	return (struct ipv4_packet *)(buff->data + ETHERNET_HEADER_SIZE);
}

int ipv4_process_packet(struct netdev *dev, struct eth_frame *frame);
int ipv4_send_packet(struct sock *sock, struct sk_buff *buffer);
