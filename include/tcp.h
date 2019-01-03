#pragma once

#include <stdint.h>
#include <netinet/in.h>
#include <string.h>

#include "skbuff.h"
#include "sock.h"
#include "eth.h"
#include "ipv4.h"
#include "utils.h"


#define TCP_HEADER_SIZE 20
#define TCP_DEFAULT_MSS 536

#define TCP_OPTIONS_END 0
#define TCP_OPTIONS_NOOP 1
#define TCP_OPTIONS_MSS 2
#define TCP_OPTIONS_WSCALE 3
#define TCP_OPTIONS_SACK_PERMITTED 4
#define TCP_OPTIONS_SACK 5
#define TCP_OPTIONS_TIMESTAMP 8

#define TCP_MAX_SOCKETS 32

// Timers
#define TCP_T_SLOW_INTERVAL 500  // slow timer should run every 500ms
#define TCP_T_FAST_INTERVAL 100  // fast timer should run every 100ms, TODO: delayed ack timer
#define TCP_T_COUNT 4  // four different timers

#define TCP_T_RETRANSMISSION 0
#define TCP_T_PERSIST 1
#define TCP_T_KEEPALIVE 2  // keep-alive OR connection-establishment timer
#define TCP_T_2MSL 3

#define TCP_TV_MSL 120 // maximum segment life in seconds, RFC 793 states 2 minutes
#define TCP_TV_RETRANSMISSION_MIN 1
#define TCP_TV_RETRANSMISSION_MAX 64
#define TCP_TV_PERSIST_MIN 5
#define TCP_TV_PERSIST_MAX 64
#define TCP_TV_KEEP_INIT 75
#define TCP_TV_KEEP_IDLE 7200

#define TCP_MAX_RETRANSMISSIONS 12
#define TCP_RTT_DEFAULT 1  // default RTT



enum tcp_state {
	CLOSED,
	LISTEN,
	SYN_RCVD,
	SYN_SENT,
	ESTABLISHED,
	CLOSE_WAIT,
	LAST_ACK,
	FIN_WAIT1,
	FIN_WAIT2,
	CLOSING,
	TIME_WAIT
};


struct tcp_options {
	uint16_t mss;
	uint8_t window_scale;
	uint8_t sack_permitted;
	uint32_t timestamp;
	uint32_t echo;
} __attribute__((packed)) tcp_options;

struct tcp_options_mss {
	uint8_t kind;
	uint8_t len;
	uint16_t value;
}  __attribute__((packed));

struct tcp_options_wscale {
	uint16_t _placeholder;
	uint8_t value;
}  __attribute__((packed));

struct tcp_options_timestamp {
	uint32_t timestamp;
	uint32_t echo;
}  __attribute__((packed));

struct tcp_packet {
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

struct tcp_socket {
	struct tcp_socket *next, *prev;
	struct sock sock;
	enum tcp_state state;
	uint16_t mss;
	uint32_t seq;
	uint32_t ack_seq;
	uint16_t timers[TCP_T_COUNT];
};

struct tcp_socket *tcp_sockets_head;



static inline struct tcp_packet *tcp_packet_from_skb(struct sk_buff *buff) {
	return (struct tcp_packet *)(buff->data + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE);
}

uint16_t tcp_checksum(struct tcp_packet *tcp_pck, uint16_t tcp_len, uint32_t source_ip, uint32_t dest_ip);
int tcp_process_packet(struct netdev *dev, struct eth_frame *frame);
int tcp_send_packet(struct tcp_socket *tcp_socket, struct sk_buff *buffer);
struct sk_buff *tcp_create_buffer(uint16_t payload_size);
int tcp_set_options(struct sk_buff *buffer, struct tcp_options* opts);
void tcp_timer_slow();


void tcp_socket_free(struct tcp_socket *tcp_sck);
struct tcp_socket* tcp_socket_new(uint32_t source_ip, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port);
struct tcp_socket* tcp_socket_get(uint32_t source_ip, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port);