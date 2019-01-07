#include <linux/if_ether.h>
#include <string.h>
#include "netinet/in.h"

#include "ipv4.h"
#include "icmp.h"
#include "tcp.h"
#include "utils.h"
#include "arp.h"


int ipv4_send_packet(struct sock *sock, struct sk_buff *buffer) {
	struct ipv4_packet *ip_packet = ipv4_packet_from_skb(buffer);

	uint16_t packet_size = (uint16_t)(buffer->size - ETHERNET_HEADER_SIZE);

	ip_packet->version = 4;
	ip_packet->protocol = sock->protocol;
	ip_packet->id = rand();  // TODO: do better than this
	ip_packet->len = htons(packet_size);
	ip_packet->header_len = (uint8_t)(IP_HEADER_SIZE >> 2);
	ip_packet->fragment_offset = htons(16384);
	ip_packet->tos = 0;
	ip_packet->ttl = IP_DEFAULT_TTL;

	ip_packet->source_ip = sock->source_ip;
	ip_packet->dest_ip = sock->dest_ip;

	ip_packet->checksum = 0;
	ip_packet->checksum = checksum((uint16_t *) ip_packet, IP_HEADER_SIZE, 0);

	// 4a:6e:c9:7a:f3:d7
	uint8_t dest_mac[] = {0x4a, 0x6e, 0xc9, 0x7a, 0xf3, 0xd7};  // TODO: lookup in ARP list
	return eth_write(sock->dev, dest_mac, ETH_P_IP, buffer);
}



int ipv4_process_packet(struct net_dev *dev, struct eth_frame *frame) {
	struct ipv4_packet *ip_packet = (struct ipv4_packet *)frame->payload;

	uint16_t checksum_orig = ip_packet->checksum;
	ip_packet->checksum = 0;
	if(checksum_orig != checksum((uint16_t *) ip_packet, sizeof(struct ipv4_packet), 0))
	{
		fprintf(stderr, "wrong checksum for ipv4 packet");
		return -1;
	}

	ip_packet->len = ntohs(ip_packet->len);
	ip_packet->id = ntohs(ip_packet->id);
	ip_packet->fragment_offset = ntohs(ip_packet->fragment_offset);
	ip_packet->checksum = checksum_orig;

	if(ip_packet->fragment_offset & IP_FLAG_MF) {
		fprintf(stderr, "received fragmented ipv4 packet (unsupported yet)\n");
		return -1;
	}

	if(ip_packet->protocol == IPPROTO_ICMP) {
		icmp_process_packet(dev, frame);
	}
	else if(ip_packet->protocol == IPPROTO_TCP) {
		tcp_in(frame);
	}
	else if(ip_packet->protocol == IPPROTO_UDP) {
		return -1;
	}
	else {
		fprintf(stderr, "unknown IPv4 protocol encountered: %d\n", ip_packet->protocol);
	}

	return 0;
}

