#pragma once

#include <stdint.h>
#include <netinet/in.h>
#include <string.h>

#include "list.h"
#include "skbuff.h"
#include "sock.h"
#include "eth.h"
#include "ipv4.h"
#include "utils.h"


#define TCP_HEADER_SIZE 20
#define TCP_INITIAL_WINDOW 64240  // initial window size


// Options
#define TCP_OPTIONS_END 0
#define TCP_OPTIONS_NOOP 1
#define TCP_OPTIONS_MSS 2
#define TCP_OPTIONS_WSCALE 3
#define TCP_OPTIONS_SACK_PERMITTED 4
#define TCP_OPTIONS_SACK 5
#define TCP_OPTIONS_TIMESTAMP 8


// Timers
#define TCP_T_SLOW_INTERVAL 500  // slow timer should run every 500ms
#define TCP_T_FAST_INTERVAL 100  // fast timer should run every 100ms, TODO: delayed ack timer


// RTO
#define TCP_RTO_ALPHA 0.125
#define TCP_RTO_BETA 0.25
#define TCP_RTO_CLOCK_GRANUALITY 100  // 100 ms
#define TCP_RTO_MIN 1000  // RTO minimum is 1 second as specified by RFC6298
#define TCP_RTO_MAX 60000  // maximum is 60 seconds


enum tcp_state {
	TCPS_CLOSED,
	TCPS_LISTEN,
	TCPS_SYN_SENT,
	TCPS_SYN_RCVD,
	TCPS_ESTABLISHED,
	TCPS_CLOSE_WAIT,
	TCPS_FIN_WAIT1,
	TCPS_CLOSING,
	TCPS_LAST_ACK,
	TCPS_FIN_WAIT2,
	TCPS_TIME_WAIT
};

struct tcp_options {
	uint16_t mss;
	uint8_t window_scale;
	uint8_t sack_permitted;
	uint32_t timestamp;
	uint32_t echo;
} __attribute__((packed)) tcp_options;

struct tcp_segment {
	uint16_t source_port;
	uint16_t dest_port;
	uint32_t seq;
	uint32_t ack_seq;
	uint8_t ns : 1, _reserved : 3, data_offset : 4;
	uint8_t fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urg_pointer;
	uint8_t data[];
}  __attribute__((packed));

struct tcp_buffer_queue_entry {
	struct tcp_buffer_queue_entry *next;
	struct sk_buff *sk_buff;
};

struct tcp_socket {
	struct list_head list;
	struct sock sock;
	struct tcp_buffer_queue_entry *out_queue_head;
	struct tcp_buffer_queue_entry *in_queue_head;

	// TCP Control Block
	enum tcp_state state;
	uint16_t mss;
	uint8_t delayed_ack;  // piggyback ACKs

	int32_t srtt;  // smoothed RTT
	int32_t rttvar;  // round-trip time variation
	uint32_t rto;  // Retransmission timeout
	uint32_t rto_expires;  // Tick count when RTO expires

	uint32_t cwnd;  // sender-side limit on the amount of data the sender can transmit before receiving an ACK
	uint32_t rwnd;  // receiver-side limit on the amount of outstanding data

	uint32_t snd_una;  // oldest unacknowledged sequence number
	uint32_t snd_nxt;  // next sequence number to be sent
	uint32_t snd_wnd;  // send window
	uint32_t snd_up;  // send urgent pointer
	uint32_t snd_wl1;  // segment sequence number used for last window update
	uint32_t snd_wl2;  // segment acknowledgment number used for last window update
	uint32_t iss;  // initial sent sequence number

	uint32_t rcv_nxt;  // next sequence number expected on an incoming segments, and is the left or lower edge of the receive window
	uint32_t rcv_wnd;  // receive window
	uint32_t rcv_up;  // receive urgent pointer
	uint32_t irs;  // initial received sequence number
};

struct list_head tcp_socket_list;


static inline struct tcp_segment *tcp_segment_from_skb(struct sk_buff *buff) {
	return (struct tcp_segment *)(buff->data + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE);
}

static inline void tcp_segment_ntoh(struct tcp_segment *tcp_segment) {
	tcp_segment->source_port = ntohs(tcp_segment->source_port);
	tcp_segment->dest_port = ntohs(tcp_segment->dest_port);
	tcp_segment->seq = ntohl(tcp_segment->seq);
	tcp_segment->ack_seq = ntohl(tcp_segment->ack_seq);
	tcp_segment->window_size = ntohs(tcp_segment->window_size);
	tcp_segment->checksum = ntohs(tcp_segment->checksum);
	tcp_segment->urg_pointer = ntohs(tcp_segment->urg_pointer);
}

uint16_t tcp_checksum(struct tcp_segment *tcp_segment, uint16_t tcp_segment_len, uint32_t source_ip, uint32_t dest_ip);
void tcp_in(struct eth_frame *frame);
struct sk_buff *tcp_out_create_buffer(uint16_t payload_size);

void tcp_out_send(struct tcp_socket *tcp_socket, struct sk_buff *buffer);
uint32_t tcp_out_data(struct tcp_socket *tcp_socket, uint8_t *data, uint32_t data_len);
void tcp_out_set_seqnums(struct tcp_socket *tcp_socket, struct sk_buff *buffer);
void tcp_out_header(struct tcp_socket *tcp_socket, struct sk_buff *buffer);
void tcp_out_ack(struct tcp_socket *tcp_socket);
void tcp_out_syn(struct tcp_socket *tcp_socket);
void tcp_out_fin(struct tcp_socket *tcp_socket);
void tcp_out_synack(struct tcp_socket *tcp_socket);
void tcp_out_rst(struct tcp_socket *tcp_socket);
void tcp_out_rstack(struct tcp_socket *tcp_socket);

void tcp_out_queue_push(struct tcp_socket *tcp_socket, struct sk_buff *sk_buff);
void tcp_out_queue_pop(struct tcp_socket *tcp_socket);
void tcp_out_queue_clear(struct tcp_socket *tcp_socket, uint32_t seq_num);

uint32_t tcp_timer_get_ticks();
void *tcp_timer_fast(void *args);
void *tcp_timer_slow(void *args);
void tcp_calc_rto(struct tcp_socket *tcp_socket);

void tcp_socket_free(struct tcp_socket *tcp_socket);
void tcp_socket_free_queues(struct tcp_socket *tcp_socket);
void tcp_socket_wait_2msl(struct tcp_socket *tcp_socket);
struct tcp_socket* tcp_socket_new(struct net_dev *device, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port);
struct tcp_socket* tcp_socket_get(uint32_t source_ip, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port);



static void debug_tcp(char *prefix, struct tcp_segment *tcp_segment, struct tcp_socket *tcp_socket) {
	printf("%s :: %d->%d | FIN %d | SYN %d | RST %d | PSH %d | ACK %d | URG %d | ECE %d | CWR %d | SEQ %u | ACK SEQ %u | WS %d | MSS %d | SRTT %d\n",
		   prefix, tcp_segment->source_port, tcp_segment->dest_port, tcp_segment->fin, tcp_segment->syn, tcp_segment->rst, tcp_segment->psh,
		   tcp_segment->ack, tcp_segment->urg, tcp_segment->ece, tcp_segment->cwr, tcp_segment->seq, tcp_segment->ack_seq, tcp_segment->window_size, tcp_socket->mss, tcp_socket->srtt);
}