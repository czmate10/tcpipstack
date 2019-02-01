#pragma once

#include <stdint.h>
#include "tap.h"
#include "eth.h"
#include "list.h"

#define ARP_HWTYPE_ETHERNET 1
#define ARP_HWSIZE_ETHERNET 6
#define ARP_PROTOLEN_IPV4 4
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_ENTRY_STATE_WAITING 1  // waiting for reply
#define ARP_ENTRY_STATE_ACTIVE 2


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

struct arp_buffer
{
	struct arp_buffer *next;
	struct sk_buff *buffer;
};

struct arp_entry
{
	struct list_head list;
	struct arp_buffer* buffer_head;
	uint8_t state;
	uint16_t protocol_type;
	uint8_t mac[6];
	uint32_t address;
};

void arp_free_cache();
struct arp_entry* arp_get_entry(uint16_t protocol_type, uint32_t address);
struct arp_entry *arp_add_entry_active(uint8_t *mac_address, uint32_t ipv4_address);
struct arp_entry *arp_send_request(struct net_dev* dev, uint32_t ipv4_address);
int arp_send_reply(struct net_dev* dev, struct arp_packet *arp_packet);
int arp_process_packet(struct net_dev *dev, struct eth_frame *eth_frame);

void arp_add_to_buffer(struct arp_entry *arp_entry, struct sk_buff *sk_buff);