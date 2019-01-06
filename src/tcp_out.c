#include <memory.h>
#include <malloc.h>
#include "tcp.h"
#include "skbuff.h"
#include "ipv4.h"


struct sk_buff *tcp_alloc(uint32_t payload_size) {
	struct sk_buff *skb = skb_alloc(ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE + payload_size);
	return skb;
}

void tcp_out_send(struct tcp_socket *tcp_sock, struct sk_buff *buffer, uint8_t opts_len) {
	struct ipv4_packet *ip_pck = ipv4_packet_from_skb(buffer);
	struct tcp_packet *tcp_pck = tcp_packet_from_skb(buffer);

	ip_pck->protocol = IPPROTO_TCP;

	// TCP fields
	tcp_pck->source_port = htons(tcp_sock->sock.source_port);
	tcp_pck->dest_port = htons(tcp_sock->sock.dest_port);
	tcp_pck->window_size = htons(tcp_sock->rcv_wnd);
	tcp_pck->data_offset = (uint8_t)((TCP_HEADER_SIZE + opts_len) >> 2);

	// Checksum
	tcp_pck->checksum = 0;
	tcp_pck->checksum = tcp_checksum(tcp_pck, (uint16_t)(buffer->size - ETHERNET_HEADER_SIZE - IP_HEADER_SIZE),
									 tcp_sock->sock.source_ip, tcp_sock->sock.dest_ip);

	ipv4_send_packet(&tcp_sock->sock, buffer);

	skb_free(buffer);
}


void tcp_out_ack(struct tcp_socket *tcp_sock) {
	struct sk_buff *buffer = tcp_create_buffer(0);
	struct tcp_packet *tcp_pck = tcp_packet_from_skb(buffer);

	tcp_pck->ack = 1;
	tcp_pck->seq = htonl(tcp_sock->snd_nxt);
	tcp_pck->ack_seq = htonl(tcp_sock->rcv_nxt);

	tcp_out_send(tcp_sock, buffer, 0);
}

void tcp_out_syn(struct tcp_socket *tcp_sock) {
	struct sk_buff *buffer = tcp_create_buffer(4);
	struct tcp_packet *tcp_pck = tcp_packet_from_skb(buffer);

	// Set state
	tcp_sock->state = TCPS_SYN_SENT;

	// TCP
	tcp_pck->syn = 1;
	tcp_pck->seq = htonl(tcp_sock->snd_nxt);
	tcp_pck->ack_seq = 0;

	// Options TODO: improve this part
	uint16_t mss = htons(tcp_sock->mss);
	tcp_pck->data[0] = TCP_OPTIONS_MSS;
	tcp_pck->data[1] = 4;
	memcpy(&tcp_pck->data[2], &mss, 2);

	// Send it
	tcp_out_send(tcp_sock, buffer, 4);

	// Increase SND.NXT
	tcp_sock->snd_nxt++;
}

void tcp_out_synack(struct tcp_socket *tcp_sock) {
	struct sk_buff *buffer = tcp_create_buffer(0);
	struct tcp_packet *tcp_pck = tcp_packet_from_skb(buffer);

	tcp_pck->ack = 0;
	tcp_pck->syn = 1;
	tcp_pck->seq = htonl(tcp_sock->snd_nxt);
	tcp_pck->ack_seq = htonl(tcp_sock->rcv_nxt);

	tcp_out_send(tcp_sock, buffer, 0);
}

void tcp_out_rst(struct tcp_socket *tcp_sock) {
	struct sk_buff *buffer = tcp_create_buffer(0);
	struct tcp_packet *tcp_pck = tcp_packet_from_skb(buffer);

	tcp_pck->rst = 1;
	tcp_pck->seq = htonl(tcp_sock->snd_nxt);
	tcp_pck->ack_seq = htonl(tcp_sock->rcv_nxt);

	tcp_out_send(tcp_sock, buffer, 0);
}

void tcp_out_rstack(struct tcp_socket *tcp_sock) {
	struct sk_buff *buffer = tcp_create_buffer(0);
	struct tcp_packet *tcp_pck = tcp_packet_from_skb(buffer);

	tcp_pck->ack = 1;
	tcp_pck->rst = 1;
	tcp_pck->seq = htonl(tcp_sock->snd_nxt);
	tcp_pck->ack_seq = htonl(tcp_sock->rcv_nxt);

	tcp_out_send(tcp_sock, buffer, 0);
}


struct sk_buff *tcp_create_buffer(uint16_t payload_size) {
	struct sk_buff *buffer = tcp_alloc(payload_size);
	struct tcp_packet *tcp_pck = tcp_packet_from_skb(buffer);

	tcp_pck->data_offset = TCP_HEADER_SIZE >> 2;

	return buffer;
}