#include <stdint.h>
#include <netinet/in.h>
#include <stdio.h>
#include <linux/if_ether.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "arp.h"
#include "tap.h"
#include "eth.h"
#include "skbuff.h"


static uint8_t BROADCAST_ADDRESS[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static LIST_HEAD(tcp_socket_list);

void arp_free_cache() {
	struct list_head *list_item, *tmp;
	struct arp_entry *entry;

	list_for_each_safe(list_item, tmp, &tcp_socket_list) {
		entry = list_entry(list_item, struct arp_entry, list);
		list_del(list_item);
		free(entry);
	}
}

struct arp_entry* arp_get_entry_ipv4(uint16_t protocol_type, uint32_t address) {
	struct list_head *list_item;
	struct arp_entry *entry;

	list_for_each(list_item, &tcp_socket_list) {
		entry = list_entry(list_item, struct arp_entry, list);
		if(entry->protocol_type == protocol_type && entry->address == address)
			return entry;
	}

	return NULL;
}

void arp_add_entry_ipv4(struct arp_packet *packet) {
	struct arp_entry *entry = malloc(sizeof(struct arp_entry));
	entry->protocol_type = packet->protocol_type;
	entry->address = packet->source_address;
	memcpy(entry->mac, packet->source_mac, sizeof(entry->mac));

	list_add(&entry->list, &tcp_socket_list);
}


int arp_send_reply(struct net_dev* dev, struct arp_packet *packet) {
	struct sk_buff *buffer = skb_alloc(ETHERNET_HEADER_SIZE + sizeof(struct arp_packet));

	buffer->dev = dev;
	struct eth_frame *eth_frame = (struct eth_frame *)buffer->data;
	struct arp_packet *packet_resp = (struct arp_packet *)eth_frame->payload;

	// Header
	packet_resp->hw_type = htons(ARP_HWTYPE_ETHERNET);
	packet_resp->protocol_type = htons(ETH_P_IP);
	packet_resp->hw_size = ARP_HWSIZE_ETHERNET;
	packet_resp->protocol_size = ARP_PROTOLEN_IPV4;
	packet_resp->op_code = htons(ARP_OP_REPLY);

	// Copy hardware addresses
	memcpy(packet_resp->source_mac, dev->hwaddr, ARP_HWSIZE_ETHERNET);
	memcpy(packet_resp->dest_mac, packet->source_mac, ARP_HWSIZE_ETHERNET);

	// Swap IPv4 addresses
	packet_resp->source_address = dev->ipv4;
	packet_resp->dest_address = packet->source_address;

	// Send it
	int bytes = eth_write(dev, BROADCAST_ADDRESS, ETH_P_ARP, buffer);
	skb_free(buffer);

	return bytes;
}


int arp_process_packet(struct net_dev *dev, struct eth_frame *eth_frame) {
	struct arp_packet *arp_packet = (struct arp_packet *)eth_frame->payload;

	arp_packet->op_code = ntohs(arp_packet->op_code);
	arp_packet->hw_type = ntohs(arp_packet->hw_type);
	arp_packet->protocol_type = ntohs(arp_packet->protocol_type);

	if(arp_packet->op_code != ARP_OP_REQUEST && arp_packet->op_code != ARP_OP_REPLY) {
		fprintf(stderr, "unknown ARP OP code: %d", arp_packet->op_code);
		return -1;
	}

	if(arp_packet->hw_type != ARP_HWTYPE_ETHERNET) {
		fprintf(stderr, "ARP hardware type unsupported: %x\n", arp_packet->hw_type);
		return -1;
	}

	if(arp_packet->hw_size != ARP_HWSIZE_ETHERNET) {
		fprintf(stderr, "ARP hardware address size mismatch: %d\n", arp_packet->hw_size);
		return -1;
	}

	if(arp_packet->protocol_type == ETH_P_IP) {
		if(arp_packet->protocol_size != ARP_PROTOLEN_IPV4) {
			fprintf(stderr, "IPv4 address size mismatch: %d\n", arp_packet->protocol_size);
			return -1;
		}

		struct arp_entry *entry = arp_get_entry_ipv4(arp_packet->protocol_type, arp_packet->source_address);

		// insert to cache if it's not in it yet
		if(!entry) {
			arp_add_entry_ipv4(arp_packet);
		}

		if(arp_packet->dest_address != dev->ipv4) {
			printf("ARP not for us, ignore\n");
			return -1;
		}

		printf("ARP reply...\n");
		return arp_send_reply(dev, arp_packet);
	}
	else {
		fprintf(stderr, "only IPv4 addresses are supported for ARP yet. requested: %x", arp_packet->protocol_type);
		return -1;
	}
}
