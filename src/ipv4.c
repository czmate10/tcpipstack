#include <linux/if_ether.h>
#include <string.h>
#include "netinet/in.h"

#include "ipv4.h"
#include "icmp.h"
#include "tcp.h"
#include "utils.h"
#include "arp.h"


int ipv4_send_packet(struct sock *sock, struct sk_buff *buffer) {
	struct ipv4_packet *ip_pck = ipv4_packet_from_skb(buffer);

	uint16_t packet_size = (uint16_t)(buffer->size - ETHERNET_HEADER_SIZE);

	ip_pck->version = 4;
	ip_pck->protocol = sock->protocol;
	ip_pck->id = rand();  // TODO: do better than this
	ip_pck->len = htons(packet_size);
	ip_pck->header_len = (uint8_t)(IP_HEADER_SIZE >> 2);
	ip_pck->fragment_offset = htons(16384);
	ip_pck->tos = 0;
	ip_pck->ttl = IP_DEFAULT_TTL;

	ip_pck->source_ip = sock->source_ip;
	ip_pck->dest_ip = sock->dest_ip;

	ip_pck->checksum = 0;
	ip_pck->checksum = checksum((uint16_t *) ip_pck, IP_HEADER_SIZE, 0);

	uint8_t dest_mac[] = {0x82, 0xa3, 0x4f, 0xa8, 0x3b, 0x71};  // TODO: lookup in ARP list
	return eth_write(sock->dev, dest_mac, ETH_P_IP, buffer);
}



int ipv4_process_packet(struct netdev *dev, struct eth_frame *frame) {
	struct ipv4_packet *ip_pck = (struct ipv4_packet *)frame->payload;

	uint16_t checksum_orig = ip_pck->checksum;
	ip_pck->checksum = 0;
	if(checksum_orig != checksum((uint16_t *) ip_pck, sizeof(struct ipv4_packet), 0))
	{
		fprintf(stderr, "wrong checksum for ipv4 packet");
		return -1;
	}

	ip_pck->len = ntohs(ip_pck->len);
	ip_pck->id = ntohs(ip_pck->id);
	ip_pck->fragment_offset = ntohs(ip_pck->fragment_offset);
	ip_pck->checksum = checksum_orig;

	if(ip_pck->fragment_offset & IP_FLAG_MF) {
		fprintf(stderr, "received fragmented ipv4 packet (unsupported yet)\n");
		return -1;
	}

	if(ip_pck->protocol == IPPROTO_ICMP) {
		icmp_process_packet(dev, frame);
	}
	else if(ip_pck->protocol == IPPROTO_TCP) {
		tcp_process_packet(dev, frame);
	}
	else if(ip_pck->protocol == IPPROTO_UDP) {
		return -1;
	}
	else {
		fprintf(stderr, "unknown IPv4 protocol encountered: %d\n", ip_pck->protocol);
	}

	return 0;
}

