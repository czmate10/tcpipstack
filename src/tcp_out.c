#include <memory.h>
#include <malloc.h>
#include "tcp.h"
#include "skbuff.h"
#include "ipv4.h"


struct sk_buff *tcp_alloc(uint32_t payload_size) {
	struct sk_buff *skb = skb_alloc(ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE + payload_size);
	return skb;
}

int tcp_send_packet(struct tcp_socket *tcp_socket, struct sk_buff *buffer) {
	struct ipv4_packet *ip_pck = ipv4_packet_from_skb(buffer);
	struct tcp_packet *tcp_pck = tcp_packet_from_skb(buffer);

	ip_pck->protocol = IPPROTO_TCP;

	tcp_pck->source_port = htons(tcp_socket->sock.source_port);
	tcp_pck->dest_port = htons(tcp_socket->sock.dest_port);
	tcp_pck->seq = htonl(tcp_socket->seq);
	tcp_pck->ack_seq = htonl(tcp_socket->ack_seq);
	tcp_pck->window_size = htons(29200);
	tcp_pck->urg_pointer = htons(0);

	uint16_t tcp_len = (uint16_t)(buffer->size - ETHERNET_HEADER_SIZE - IP_HEADER_SIZE);
	tcp_pck->checksum = tcp_checksum(tcp_pck, tcp_len, tcp_socket->sock.source_ip, tcp_socket->sock.dest_ip);

	return ipv4_send_packet(&tcp_socket->sock, buffer);
}

struct sk_buff *tcp_create_buffer(uint16_t payload_size) {
	struct sk_buff *buffer = tcp_alloc(payload_size);
	struct tcp_packet *tcp_pck = tcp_packet_from_skb(buffer);

	tcp_pck->data_offset = TCP_HEADER_SIZE / 4;

	return buffer;
}

int tcp_set_options(struct sk_buff *buffer, struct tcp_options* opts) {
	struct tcp_packet *tcp_pck = tcp_packet_from_skb(buffer);
	uint8_t header_len = 0;  // how many 32-bit words
	if(opts->mss != 0) {
		struct tcp_options_mss *opts_mss = (struct tcp_options_mss *) tcp_pck->data;
		opts_mss->kind = TCP_OPTIONS_MSS;
		opts_mss->len = 4;
		opts_mss->value = htons(opts->mss);

		header_len += 1;
	}

	tcp_pck->data_offset = (sizeof(struct tcp_packet) / 4) + header_len;
	return 0;
}