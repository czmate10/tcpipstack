#include <linux/icmp.h>
#include <memory.h>

#include "icmp.h"
#include "utils.h"


int icmp_process_packet(struct netdev *dev, struct eth_frame *frame) {
	struct ipv4_packet *ip_pck = (struct ipv4_packet *)frame->payload;
	struct icmp_v4_packet *icmp_pck = (struct icmp_v4_packet *)(ip_pck->data + ((ip_pck->header_len*4) - sizeof(struct ipv4_packet)));

	uint32_t icmp_packet_size = ip_pck->len - (ip_pck->header_len * (uint16_t) 4);

	icmp_pck->checksum = ntohs(icmp_pck->checksum);

	struct sock socket;
	socket.source_ip = ip_pck->dest_ip;
	socket.dest_ip = ip_pck->source_ip;
	socket.protocol = IPPROTO_ICMP;
	socket.dev = dev;

	if(icmp_pck->type == ICMP_ECHO) {
		// Echo request
		struct sk_buff *buffer = skb_alloc(ETHERNET_HEADER_SIZE + ip_pck->len);
		struct icmp_v4_packet *icmp_pck_resp = icmp_v4_packet_from_skb(buffer);

		// Echo reply
		icmp_pck_resp->type = ICMP_ECHOREPLY;
		icmp_pck_resp->code = 0;

		// Copy the data
		memcpy(icmp_pck_resp->data, icmp_pck->data, icmp_packet_size - sizeof(struct icmp_v4_packet));

		// Calculate checksum
		icmp_pck_resp->checksum = checksum((uint16_t *) icmp_pck, icmp_packet_size, 0);

		return ipv4_send_packet(&socket, buffer);
	}
	else if(icmp_pck->type == ICMP_DEST_UNREACH) {
		fprintf(stderr, "ICMP - destination unreachable, code: %d", icmp_pck->code);
		return -1;
	}
	else if(icmp_pck->type == ICMP_TIME_EXCEEDED) {
		fprintf(stderr, "ICMP - time exceeded, code: %d", icmp_pck->code);
	}
	else {
		fprintf(stderr, "unknown ICMP request type: %d", icmp_pck->type);
	}

	return -1;
}