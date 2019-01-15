#pragma once

#include <stdint.h>
#include "tap.h"
#include "eth.h"

#define ARP_HWTYPE_ETHERNET 1
#define ARP_HWSIZE_ETHERNET 6
#define ARP_PROTOLEN_IPV4 4
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_CACHE_SIZE 128


struct arp_packet
{
	uint16_t hw_type;
	uint16_t protocol_type;
	uint8_t hw_size;
	uint8_t protocol_size;
	uint16_t op_code;
	uint8_t source_mac[6];
	uint32_t source_address;
	uint8_t dest_mac[6];
	uint32_t dest_address;
} __attribute__((packed));

struct arp_entry
{
	uint16_t protocol_type;
	uint8_t mac[6];
	uint32_t address;
};


struct arp_entry arp_cache[ARP_CACHE_SIZE];

void arp_free_caches();
struct arp_entry* arp_get_entry_ipv4(uint16_t protocol_type, uint32_t address);
int arp_add_entry_ipv4(struct arp_packet *packet);
int arp_send_reply(struct net_dev* dev, struct arp_packet *arp_packet);
int arp_process_packet(struct net_dev *dev, struct eth_frame *eth_frame);
