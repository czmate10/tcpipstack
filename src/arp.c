#include <stdint.h>
#include <netinet/in.h>
#include <stdio.h>
#include <linux/if_ether.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "arp.h"
#include "tap.h"
#include "eth.h"
#include "skbuff.h"


static uint8_t BROADCAST_ADDRESS[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static LIST_HEAD(arp_entry_list);
pthread_mutex_t arp_mutex = PTHREAD_MUTEX_INITIALIZER;

void arp_free_cache() {
	struct list_head *list_item, *tmp;
	struct arp_entry *entry;

	pthread_mutex_lock(&arp_mutex);

	list_for_each_safe(list_item, tmp, &arp_entry_list) {
		entry = list_entry(list_item, struct arp_entry, list);

		// Clean up ARP buffer too
		struct arp_buffer *buffer = entry->buffer_head;
		while(buffer != NULL) {
			skb_free(buffer->buffer);

			struct arp_buffer *buffer_next = buffer->next;
			free(buffer);
			buffer = buffer_next;
		}

		list_del(list_item);
		free(entry);
	}


	pthread_mutex_unlock(&arp_mutex);
}

struct arp_entry* arp_get_entry(uint16_t protocol_type, uint32_t address) {
	struct list_head *list_item;
	struct arp_entry *entry;

	pthread_mutex_lock(&arp_mutex);

	list_for_each(list_item, &arp_entry_list) {
		entry = list_entry(list_item, struct arp_entry, list);
		if(entry->protocol_type == protocol_type && entry->address == address) {
			pthread_mutex_unlock(&arp_mutex);
			return entry;
		}
	}

	pthread_mutex_unlock(&arp_mutex);

	return NULL;
}

struct arp_entry *arp_add_entry_active(uint8_t *mac_address, uint32_t ipv4_address) {
	pthread_mutex_lock(&arp_mutex);

	struct arp_entry *entry = malloc(sizeof(struct arp_entry));
	entry->buffer_head = NULL;
	entry->state = ARP_ENTRY_STATE_ACTIVE;
	entry->protocol_type = ETH_P_IP;
	entry->address = ipv4_address;
	memcpy(entry->mac, mac_address, sizeof(entry->mac));
	list_add(&entry->list, &arp_entry_list);

	pthread_mutex_unlock(&arp_mutex);
	return entry;
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
	return eth_write(BROADCAST_ADDRESS, ETH_P_ARP, buffer);
}

struct arp_entry *arp_send_request(struct net_dev* dev, uint32_t ipv4_address) {
	// First create the entry in SENT state
	pthread_mutex_lock(&arp_mutex);

	struct arp_entry *entry = malloc(sizeof(struct arp_entry));
	entry->buffer_head = NULL;
	entry->state = ARP_ENTRY_STATE_WAITING;
	entry->protocol_type = ETH_P_IP;
	entry->address = ipv4_address;
	memset(entry->mac, 0, ARP_HWSIZE_ETHERNET);
	list_add(&entry->list, &arp_entry_list);

	pthread_mutex_unlock(&arp_mutex);

	// Send the request
	struct sk_buff *buffer = skb_alloc(ETHERNET_HEADER_SIZE + sizeof(struct arp_packet));

	buffer->dev = dev;
	struct eth_frame *eth_frame = (struct eth_frame *)buffer->data;
	struct arp_packet *packet = (struct arp_packet *)eth_frame->payload;

	// Header
	packet->hw_type = htons(ARP_HWTYPE_ETHERNET);
	packet->protocol_type = htons(ETH_P_IP);
	packet->hw_size = ARP_HWSIZE_ETHERNET;
	packet->protocol_size = ARP_PROTOLEN_IPV4;
	packet->op_code = htons(ARP_OP_REQUEST);

	// Copy hardware addresses
	memcpy(packet->source_mac, dev->hwaddr, ARP_HWSIZE_ETHERNET);
	memcpy(packet->dest_mac, BROADCAST_ADDRESS, ARP_HWSIZE_ETHERNET);

	// Swap IPv4 addresses
	packet->source_address = dev->ipv4;
	packet->dest_address = ipv4_address;

	// Send it
	eth_write(BROADCAST_ADDRESS, ETH_P_ARP, buffer);

	return entry;
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

		struct arp_entry *entry = arp_get_entry(arp_packet->protocol_type, arp_packet->source_address);

		// check if IP is not in cache yet, or we were waiting for reply
		if(!entry)
			arp_add_entry_active(arp_packet->source_mac, arp_packet->source_address);

		else if(entry->state == ARP_ENTRY_STATE_WAITING) {
			// Received reply for sent request
			pthread_mutex_lock(&arp_mutex);
			memcpy(entry->mac, arp_packet->source_mac, ARP_HWSIZE_ETHERNET);
			entry->state = ARP_ENTRY_STATE_ACTIVE;

			while(entry->buffer_head != NULL) {
				eth_write(entry->mac, entry->protocol_type, entry->buffer_head->buffer);

				struct arp_buffer *buffer_next = entry->buffer_head->next;
				free(entry->buffer_head);
				entry->buffer_head = buffer_next;
			}

			pthread_mutex_unlock(&arp_mutex);
		}

		if(arp_packet->dest_address != dev->ipv4) {
			printf("ARP not for us, ignore\n");
			return -1;
		}

		if(arp_packet->op_code == ARP_OP_REQUEST)
			return arp_send_reply(dev, arp_packet);
		else
			return 0;
	}
	else {
		fprintf(stderr, "only IPv4 addresses are supported for ARP yet. requested: %x", arp_packet->protocol_type);
		return -1;
	}
}


void arp_add_to_buffer(struct arp_entry *arp_entry, struct sk_buff *sk_buff) {
	struct arp_buffer* arp_buffer = malloc(sizeof(struct arp_buffer));
	arp_buffer->next = NULL;
	arp_buffer->buffer = sk_buff;

	pthread_mutex_lock(&arp_mutex);

	if(arp_entry->buffer_head == NULL)
		arp_entry->buffer_head = arp_buffer;
	else {
		struct arp_buffer *tail = arp_entry->buffer_head;
		while(tail->next != NULL)
			tail = tail->next;

		tail->next = arp_buffer;
	}

	pthread_mutex_unlock(&arp_mutex);
}
