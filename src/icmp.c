#include <linux/icmp.h>
#include <memory.h>

#include "icmp.h"
#include "utils.h"


int icmp_process_packet(struct net_dev *dev, struct eth_frame *frame) {
	struct ipv4_packet *ip_packet = (struct ipv4_packet *)frame->payload;
	struct icmp_v4_packet *icmp_packet = (struct icmp_v4_packet *)(ip_packet->data + ((ip_packet->header_len*4) - sizeof(struct ipv4_packet)));

	uint32_t icmp_packet_size = ip_packet->len - (ip_packet->header_len * (uint16_t) 4);

	uint16_t checksum_orig = icmp_packet->checksum;
	icmp_packet->checksum = 0;
	uint16_t checksum_actual = checksum((uint16_t *)icmp_packet, icmp_packet_size, 0);

	if(checksum_orig != checksum_actual) {
		fprintf(stderr, "wrong checksum for ICMP packet");
		return -1;
	}

	struct sock socket;
	socket.source_ip = ip_packet->dest_ip;
	socket.dest_ip = ip_packet->source_ip;
	socket.protocol = IPPROTO_ICMP;
	socket.dev = dev;

	if(icmp_packet->type == ICMP_ECHO) {
		// Echo request
		struct sk_buff *buffer = skb_alloc(ETHERNET_HEADER_SIZE + ip_packet->len);
		struct icmp_v4_packet *icmp_packet_response = icmp_v4_packet_from_skb(buffer);

		// Echo reply
		icmp_packet_response->type = ICMP_ECHOREPLY;
		icmp_packet_response->code = 0;

		// Copy the data
		memcpy(icmp_packet_response->data, icmp_packet->data, icmp_packet_size - sizeof(struct icmp_v4_packet));

		// Calculate checksum
		icmp_packet_response->checksum = checksum((uint16_t *)icmp_packet_response, icmp_packet_size, 0);

		return ipv4_send_packet(&socket, buffer);
	}
	else if(icmp_packet->type == ICMP_DEST_UNREACH) {
		fprintf(stderr, "ICMP - destination unreachable, code: %d", icmp_packet->code);
		return -1;
	}
	else if(icmp_packet->type == ICMP_TIME_EXCEEDED) {
		fprintf(stderr, "ICMP - time exceeded, code: %d", icmp_packet->code);
	}
	else {
		fprintf(stderr, "unknown ICMP request type: %d", icmp_packet->type);
	}

	return -1;
}