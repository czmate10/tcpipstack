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


struct arp_entry* arp_get_entry_ipv4(uint16_t protocol_type, uint32_t address) {
	for(int i = 0; i < ARP_CACHE_SIZE; i++) {
		struct arp_entry *entry = &arp_cache[i];
		if(entry->protocol_type == 0)  // We have no entries in the cache after this, TODO: find a better way to do this check
			break;

		if(entry->protocol_type == protocol_type && entry->address == address) {
			return entry;
		}
	}

	return NULL;
}

int arp_add_entry_ipv4(struct arp_packet *packet, struct arp_payload* payload) {
	struct arp_entry *entry = NULL;

	for(int i = 0; i < ARP_CACHE_SIZE; i++) {
		entry = &arp_cache[i];
		if(entry->protocol_type == 0)  // We have no entries in the cache after this
			break;
	}

	if(entry->protocol_type != 0) {  // We have ran out of space in our cache, TODO: do something when this happens
		fprintf(stderr, "ARP cache is out of space!\n");
		return 0;
	}

	entry->protocol_type = packet->protocol_type;
	entry->address = payload->source_address;
	memcpy(entry->mac, payload->source_mac, sizeof(entry->mac));

	return 1;
}


int arp_send_reply(struct netdev* dev, struct eth_frame *eth_frame) {
	struct arp_packet *arp_pck = (struct arp_packet *)eth_frame->payload;
	struct arp_payload *entry_data = (struct arp_payload *)arp_pck->data;

	// Swap hardware addresses
	memcpy(entry_data->dest_mac, entry_data->source_mac, sizeof(entry_data->dest_mac));
	memcpy(entry_data->source_mac, dev->hwaddr, sizeof(entry_data->source_mac));

	// Swap IPv4 addresses
	entry_data->dest_address = entry_data->source_address;
	entry_data->source_address = dev->ipv4;

	// Set OP field
	arp_pck->op_code = ARP_OP_REPLY;

	// Convert endianness
	arp_pck->op_code = htons(arp_pck->op_code);
	arp_pck->protocol_type = htons(arp_pck->protocol_type);
	arp_pck->hw_type = htons(arp_pck->hw_type);

	// Send it
	return eth_write_raw(dev, entry_data->dest_mac, ETH_P_ARP, eth_frame, sizeof(arp_pck) + sizeof(struct arp_payload));
}


int arp_process_packet(struct netdev *dev, struct eth_frame *eth_frame) {
	struct arp_packet *arp_pck = (struct arp_packet *)eth_frame->payload;

	arp_pck->op_code = ntohs(arp_pck->op_code);
	arp_pck->hw_type = ntohs(arp_pck->hw_type);
	arp_pck->protocol_type = ntohs(arp_pck->protocol_type);

	if(arp_pck->op_code != ARP_OP_REQUEST && arp_pck->op_code != ARP_OP_REPLY) {
		fprintf(stderr, "unknown ARP OP code: %d", arp_pck->op_code);
		return -1;
	}

	if(arp_pck->hw_type != ARP_HWTYPE_ETHERNET) {
		fprintf(stderr, "ARP hardware type unsupported: %x\n", arp_pck->hw_type);
		return -1;
	}

	if(arp_pck->hw_size != ARP_HWSIZE_ETHERNET) {
		fprintf(stderr, "ARP hardware address size mismatch: %d\n", arp_pck->hw_size);
		return -1;
	}

	if(arp_pck->protocol_type == ETH_P_IP) {
		if(arp_pck->protocol_size != ARP_PROTOLEN_IPV4) {
			fprintf(stderr, "IPv4 address size mismatch: %d\n", arp_pck->protocol_size);
			return -1;
		}

		struct arp_payload *entry_data = (struct arp_payload *)arp_pck->data;
		struct arp_entry *entry = arp_get_entry_ipv4(arp_pck->protocol_type, entry_data->source_address);

		// insert to cache if it's not in it yet
		if(!entry) {
			arp_add_entry_ipv4(arp_pck, entry_data);
		}

		if(entry_data->dest_address != dev->ipv4) {
			printf("ARP not for us, ignore\n");
			return -1;
		}

		return arp_send_reply(dev, eth_frame);
	}
	else {
		fprintf(stderr, "only IPv4 addresses are supported for ARP yet. requested: %x", arp_pck->protocol_type);
		return -1;
	}
}
