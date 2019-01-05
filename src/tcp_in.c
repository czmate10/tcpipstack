#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "ipv4.h"
#include "tcp.h"
#include "utils.h"


void tcp_parse_options(struct tcp_options *opts, uint8_t *data, uint8_t size) {
	opts->mss = TCP_DEFAULT_MSS; // Default

	uint8_t* ptr = data;
	while(ptr < data + size) {
		if (*ptr == TCP_OPTIONS_END) {
			break;
		}

		else if(*ptr == TCP_OPTIONS_NOOP) {
			ptr++;
		}

		else if(*ptr == TCP_OPTIONS_MSS) {
			struct tcp_options_mss* mss = (struct tcp_options_mss*)ptr;
			opts->mss = ntohs(mss->value);
			ptr += sizeof(struct tcp_options_mss);
		}

		else if(*ptr == TCP_OPTIONS_WSCALE) {
			struct tcp_options_wscale* wscale = (struct tcp_options_wscale*)ptr;
			opts->window_scale = wscale->value;
			ptr += sizeof(struct tcp_options_wscale);
		}

		else if(*ptr == TCP_OPTIONS_SACK_PERMITTED) {
			opts->sack_permitted = 1;
			ptr += 2;
		}

		else if(*ptr == TCP_OPTIONS_SACK) {
			// TODO
			fprintf(stderr, "sack not implemented");
			exit(1);
		}

		else if(*ptr == TCP_OPTIONS_TIMESTAMP) {
			struct tcp_options_timestamp* ts = (struct tcp_options_timestamp*)ptr;
			opts->timestamp = ntohl(ts->timestamp);
			opts->echo = ntohl(ts->echo);
			ptr += sizeof(struct tcp_options_timestamp);
		}

		else {
			fprintf(stderr, "unknown TCP option encountered: %d, size: %d", *ptr, size);
			exit(1);
		}
	}
}

int tcp_process_packet(struct netdev *dev, struct eth_frame *frame) {
	struct ipv4_packet *ip_pck = (struct ipv4_packet *)frame->payload;
	struct tcp_packet *tcp_pck = (struct tcp_packet *)(ip_pck->data + ((ip_pck->header_len*4) - sizeof(struct ipv4_packet)));

	uint16_t checksum = tcp_pck->checksum;
	if(checksum != tcp_checksum(tcp_pck, (uint16_t)(ip_pck->len - ip_pck->header_len*4), ip_pck->source_ip, ip_pck->dest_ip)) {
		fprintf(stderr, "TCP packet has mismatching checksum!\n");
		return -1;
	}

	tcp_pck->source_port = ntohs(tcp_pck->source_port);
	tcp_pck->dest_port = ntohs(tcp_pck->dest_port);
	tcp_pck->seq = ntohl(tcp_pck->seq);
	tcp_pck->ack_seq = ntohl(tcp_pck->ack_seq);
	tcp_pck->window_size = ntohs(tcp_pck->window_size);
	tcp_pck->checksum = ntohs(tcp_pck->checksum);
	tcp_pck->urg_pointer = ntohs(tcp_pck->urg_pointer);

	// Get options
	struct tcp_options *opts = calloc(0, sizeof(struct tcp_options));
	if(opts == NULL) {
		perror("could not allocate memory for TCP options");
		exit(1);
	}

	uint8_t options_size = (uint8_t) ((tcp_pck->data_offset - 5) << 4);
	if(options_size > 0)
		tcp_parse_options(opts, tcp_pck->data, options_size);
	else
		opts->mss = TCP_DEFAULT_MSS;

	// Get payload start
	uint16_t payload_size = ip_pck->len - sizeof(struct ipv4_packet) - sizeof(struct tcp_packet) - options_size;
	uint8_t *payload = tcp_pck->data + options_size;

	printf("TCP :: Payload size: %d | Options size: %d | MSS: %d | %d -> %d\n",
			payload_size, options_size, opts->mss, tcp_pck->source_port, tcp_pck->dest_port);

	struct tcp_socket *socket = tcp_socket_get(ip_pck->dest_ip, ip_pck->source_ip, tcp_pck->dest_port, tcp_pck->source_port);

	printf("FIN %d | SYN %d | RST %d | PSH %d | ACK %d | URG %d | ECE %d | CWR %d | SEQ %u | WS %d\n",
			tcp_pck->fin, tcp_pck->syn, tcp_pck->rst, tcp_pck->psh, tcp_pck->ack, tcp_pck->urg, tcp_pck->ece,
			tcp_pck->cwr, tcp_pck->seq, tcp_pck->window_size);

	if(socket == NULL && tcp_pck->syn) {
		// New connection
		socket = tcp_socket_new(ip_pck->dest_ip, ip_pck->source_ip, tcp_pck->dest_port, tcp_pck->source_port);
		socket->sock.dev = dev;
		socket->seq = 1000;  // TODO: not constant
		socket->ack_seq = tcp_pck->seq + 1;
		socket->mss = opts->mss;
		socket->state = SYN_RCVD;

		struct sk_buff *buffer = tcp_create_buffer(4);
		struct tcp_packet *tcp_pck_reply = tcp_packet_from_skb(buffer);

		tcp_pck_reply->syn = 1;
		tcp_pck_reply->ack = 1;

		// Set options
		opts->mss = socket->mss;
		opts->sack_permitted = 0;
		opts->timestamp = 0;
		opts->echo = 0;
		opts->window_scale = 0;
		tcp_set_options(buffer, opts);

		tcp_send_packet(socket, buffer);
		skb_free(buffer);
	}

	else if(!socket) {
		printf("TCP packet dropped (no active connection): %d -> %d\n", tcp_pck->source_port, tcp_pck->dest_port);
	}

	else if(socket->state == SYN_RCVD && tcp_pck->ack && tcp_pck->ack_seq == socket->seq + 1) {
		socket->state = ESTABLISHED;
		socket->seq++;
	}

	else if(socket->state == ESTABLISHED) {
		if(tcp_pck->fin) {
			// CLOSE_WAIT
			socket->ack_seq = tcp_pck->seq + 1;
			socket->state = CLOSE_WAIT;

			struct sk_buff *buffer = tcp_create_buffer(0);
			struct tcp_packet *tcp_pck_reply = tcp_packet_from_skb(buffer);

			tcp_pck_reply->ack = 1;

			tcp_send_packet(socket, buffer);
			skb_free(buffer);

			// LAST_ACK
			struct sk_buff *buffer2 = tcp_create_buffer(0);
			socket->state = LAST_ACK;

			tcp_pck_reply = tcp_packet_from_skb(buffer2);

			tcp_pck_reply->ack = 1;
			tcp_pck_reply->fin = 1;

			tcp_send_packet(socket, buffer2);
			skb_free(buffer2);
		}
		// PSH
		if(tcp_pck->psh) {
			socket->ack_seq = tcp_pck->seq + payload_size;

			struct sk_buff *buffer = tcp_create_buffer(0);
			struct tcp_packet *tcp_pck_reply = tcp_packet_from_skb(buffer);

			tcp_pck_reply->ack = 1;

			printf("\nReceived (%d bytes):\n--------------------\n%.*s\n--------------------\n",
					payload_size, payload_size, payload);

			tcp_send_packet(socket, buffer);
			skb_free(buffer);
		}
	}

	else if(socket->state == LAST_ACK && tcp_pck->ack) {
		// Connection fully closed
		tcp_socket_free(socket);
		printf("Connection fully closed!\n");
}

//	if(payload_size > 0)
//		printf("-----------------------\n%s\n-----------------------\n\n", payload);


free(opts);
return 0;
}
