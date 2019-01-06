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

void tcp_process_syn_sent(struct tcp_socket *socket, struct tcp_packet *tcp_pck, struct tcp_options *opts) {
	// 1: check ACK
	if(tcp_pck->ack) {
		if (tcp_pck->ack_seq <= socket->iss || tcp_pck->ack_seq > socket->snd_nxt) {
			return; // TODO: check RST flag
		}

		if (tcp_pck->ack_seq < socket->snd_una || tcp_pck->ack_seq > socket->snd_nxt) {
			return;
		}
	}

	// 2: check RST bit
	if (tcp_pck->rst) {
		fprintf(stderr, "error: connection reset");
		tcp_socket_free(socket);
		return;
	}

	// TODO: 3: check security

	// 4: check the SYN bit
	if(tcp_pck->syn) {
		socket->rcv_nxt = tcp_pck->seq + 1;
		socket->irs = tcp_pck->seq;
		if(tcp_pck->ack) {
			socket->snd_una = tcp_pck->ack_seq;
			// TODO:  any segments on the retransmission queue which
			//        are thereby acknowledged should be removed.
		}

		if(socket->snd_una > socket->iss) {
			// Our SYN has been ACKed
			printf("TCP IN :: established connection\n");
			socket->state = TCPS_ESTABLISHED;
			tcp_out_ack(socket);
		}
		else {
			socket->state = TCPS_SYN_RCVD;
			socket->snd_una = socket->iss;
			tcp_out_synack(socket);
		}
	}
}

void tcp_process_listen(struct tcp_socket *socket, struct tcp_packet *tcp_pck, struct tcp_options *opts) {
}

void tcp_process_closed(struct tcp_socket *socket, struct tcp_packet *tcp_pck, struct tcp_options *opts, uint16_t tcp_segment_size) {
	if(tcp_pck->rst)
		return;

	// Send RST
	if(tcp_pck->ack) {
		socket->snd_nxt = tcp_pck->ack_seq;
		tcp_out_rst(socket);
	}
	else {
		socket->rcv_nxt = tcp_pck->seq + tcp_segment_size;
		socket->snd_nxt = 0;
		tcp_out_rstack(socket);
	}
}

int tcp_accept_test(struct tcp_socket *socket, struct tcp_packet *tcp_pck, uint16_t tcp_segment_size) {
	if(tcp_segment_size == 0 && socket->rcv_wnd == 0) {
		return tcp_pck->seq == socket->rcv_nxt;
	}

	else if(tcp_segment_size == 0 && socket->rcv_wnd > 0)
		return socket->rcv_nxt <= tcp_pck->seq < (socket->rcv_nxt + socket->rcv_wnd);

	else if(tcp_segment_size > 0 && socket->rcv_wnd == 0)
		return 0;

	else if(tcp_segment_size > 0 && socket->rcv_wnd > 0)
		return ((socket->rcv_nxt <= tcp_pck->seq < socket->rcv_nxt+socket->rcv_wnd) ||
				(socket->rcv_nxt <= tcp_pck->seq + tcp_segment_size - 1 < socket->rcv_nxt+socket->rcv_wnd));

	return 0;
}

uint8_t tcp_process_options(struct tcp_packet *tcp_pck, struct tcp_options **opts) {
	*opts = calloc(0, sizeof(struct tcp_options));
	if (*opts == NULL) {
		perror("could not allocate memory for TCP options");
		exit(1);
	}

	uint8_t options_size = (uint8_t) ((tcp_pck->data_offset - 5) << 4);
	if (options_size > 0)
		tcp_parse_options(*opts, tcp_pck->data, options_size);
	else
		(*opts)->mss = TCP_DEFAULT_MSS;

	return options_size;
}

int tcp_process_packet(struct netdev *dev, struct eth_frame *frame) {
	struct ipv4_packet *ip_pck = (struct ipv4_packet *) frame->payload;
	struct tcp_packet *tcp_pck = (struct tcp_packet *) (ip_pck->data +
														((ip_pck->header_len * 4) - sizeof(struct ipv4_packet)));

	uint16_t checksum = tcp_pck->checksum;
	uint16_t tcp_packet_size = (uint16_t)(ip_pck->len - ip_pck->header_len * 4);
	uint16_t tcp_segment_size = (uint16_t)(tcp_packet_size - TCP_HEADER_SIZE);

	// Compare checksums
	if (checksum != tcp_checksum(tcp_pck, tcp_packet_size, ip_pck->source_ip, ip_pck->dest_ip)) {
		fprintf(stderr, "TCP packet has mismatching checksum!\n");
		return -1;
	}

	// ntoh
	tcp_packet_ntoh(tcp_pck);

	// Get socket
	struct tcp_socket *socket = tcp_socket_get(ip_pck->dest_ip, ip_pck->source_ip, tcp_pck->dest_port,
											   tcp_pck->source_port);
	if (!socket || socket->state == TCPS_CLOSED) {
		// TODO: If there is no RST flag present, send RST
		printf("TCP packet dropped (no active connection): %d -> %d\n", tcp_pck->source_port, tcp_pck->dest_port);
		return -1;
	}

	// Debug print
	printf("TCP IN :: %d->%d | FIN %d | SYN %d | RST %d | PSH %d | ACK %d | URG %d | ECE %d | CWR %d | SEQ %u | WS %d | MSS %d\n",
		   tcp_pck->source_port, tcp_pck->dest_port, tcp_pck->fin, tcp_pck->syn, tcp_pck->rst, tcp_pck->psh,
		   tcp_pck->ack, tcp_pck->urg, tcp_pck->ece, tcp_pck->cwr, tcp_pck->seq, tcp_pck->window_size, socket->mss);

	// Get options
	struct tcp_options *opts;
	uint8_t options_size = tcp_process_options(tcp_pck, &opts);


	// First check if we are in one of these 3 states
	if(socket->state == TCPS_SYN_SENT) {
		tcp_process_syn_sent(socket, tcp_pck, opts);
		return 0;
	}
	else if(socket->state == TCPS_LISTEN) {
		tcp_process_listen(socket, tcp_pck, opts);
		return 0;
	}
	else if(socket->state == TCPS_CLOSED) {
		tcp_process_closed(socket, tcp_pck, opts, tcp_packet_size);
		return 0;
	}

	// 1: check sequence number
	if(!tcp_accept_test(socket, tcp_pck, tcp_segment_size)) {
		fprintf(stderr, "Invalid TCP ack sequence num: %u - sending RST\n", tcp_pck->ack_seq);

		if(!tcp_pck->rst)
			tcp_out_ack(socket);

		return -1;
	}

	// 2: check the RST bit
	if(tcp_pck->rst) {
		switch(socket->state) {
			case TCPS_SYN_RCVD:
				// If passive open, set to LISTEN stage
				// If active open, connection was refused
				fprintf(stderr, "connection refused\n");
				socket->state = TCPS_CLOSED;  // or LISTEN if passive open
				tcp_socket_free(socket);
				return -1;

			case TCPS_ESTABLISHED:
			case TCPS_FIN_WAIT1:
			case TCPS_FIN_WAIT2:
			case TCPS_CLOSE_WAIT:
				// TODO: flush segment queues
				fprintf(stderr, "connection reset\n");
				socket->state = TCPS_CLOSED;
				tcp_socket_free(socket);
				return -1;

			case TCPS_CLOSING:
			case TCPS_LAST_ACK:
			case TCPS_TIME_WAIT:
				socket->state = TCPS_CLOSED;
				tcp_socket_free(socket);
				return -1;

			default:
				fprintf(stderr, "unknown state for socket: %d\n", socket->state);
				return -1;
		}
	}

	// 3: check security
	// -----------------

	// 4: check the SYN bit
	if(tcp_pck->syn) {
		switch(socket->state) {
			case TCPS_SYN_RCVD:
			case TCPS_ESTABLISHED:
			case TCPS_FIN_WAIT1:
			case TCPS_FIN_WAIT2:
			case TCPS_CLOSE_WAIT:
			case TCPS_CLOSING:
			case TCPS_LAST_ACK:
			case TCPS_TIME_WAIT:
				// TODO: flush segment queues
				fprintf(stderr, "connection reset\n");
				tcp_out_rst(socket);
				socket->state = TCPS_CLOSED;
				tcp_socket_free(socket);
				return -1;
		}
	}

	// 5: check ACK field
	if(!tcp_pck->ack)
		return -1;

	switch(socket->state) {
		case TCPS_TIME_WAIT:
			tcp_out_ack(socket);
			// TODO: restart 2MSL timer here
			return 0;

		case TCPS_LAST_ACK:
			// FIN acknowledged
			tcp_socket_free(socket);
			return 0;

		case TCPS_SYN_RCVD:
			if(socket->snd_una <= tcp_pck->ack_seq <= socket->snd_nxt) {
				socket->state = TCPS_ESTABLISHED;
				// Continue processing
			}
			else {
				tcp_out_rst(socket);
				return 0;
			}
		case TCPS_FIN_WAIT1:
			socket->state = TCPS_FIN_WAIT2;
		case TCPS_FIN_WAIT2:
			// close is acknowledged, but don't delete the TCB yet
		case TCPS_CLOSING:
			socket->state = TCPS_TIME_WAIT;
		case TCPS_CLOSE_WAIT:
		case TCPS_ESTABLISHED:
			if(socket->snd_una < tcp_pck->ack_seq <= socket->snd_nxt) {
				socket->snd_una = tcp_pck->ack_seq;
				// TODO: remove acknowledged segments in the buffer

				// Set send window, but not if it's an old segment (snd_wl1, snd_wl2)
				if(socket->snd_wl1 < tcp_pck->seq || (socket->snd_wl1 == tcp_pck->seq && socket->snd_wl2 <= tcp_pck->ack_seq)) {
					socket->snd_wnd = tcp_pck->window_size;
					socket->snd_wl1 = tcp_pck->seq;
					socket->snd_wl2 = tcp_pck->ack_seq;
				}
			}
			else if(tcp_pck->ack_seq > socket->snd_nxt) {
				// Not yet sent
				tcp_out_ack(socket);
				return 0;
			}
	}

	// 6: check URG bit

	// 7: process segment text
	switch(socket->state) {
		case TCPS_ESTABLISHED:
		case TCPS_FIN_WAIT1:
		case TCPS_FIN_WAIT2: {
			uint16_t payload_size = ip_pck->len - sizeof(struct ipv4_packet) - sizeof(struct tcp_packet) - options_size;

			if (tcp_pck->psh && payload_size > 0) {
				// Get payload
				uint8_t *payload = tcp_pck->data + options_size;

				// Set rcv_next
				socket->rcv_nxt += payload_size;

				// Debug print
				printf("\nReceived (%d bytes):\n--------------------\n%.*s\n--------------------\n",
					   payload_size, payload_size, payload);

				tcp_out_ack(socket);  // TODO: should be piggybacked
			}
			break;
		}

		case TCPS_CLOSE_WAIT:
		case TCPS_CLOSING:
		case TCPS_LAST_ACK:
		case TCPS_TIME_WAIT:
			// This should not occur, since a FIN has been received from the
			// remote side. Ignore the segment text.
			break;

		default:
			fprintf(stderr, "unknown state for socket: %d\n", socket->state);
			return -1;
	}

	// 8: check FIN bit
	if(tcp_pck->fin) {
		switch (socket->state) {
			case TCPS_CLOSED:
			case TCPS_LISTEN:
			case TCPS_SYN_SENT:
				// SEG.SEQ cannot be validated; drop the segment
				return 0;

			case TCPS_SYN_RCVD:
			case TCPS_ESTABLISHED:
				printf("TCP :: closing connection\n");

				socket->rcv_nxt = tcp_pck->seq+1;
				tcp_out_ack(socket);

				socket->state = TCPS_CLOSE_WAIT;
				break;

			case TCPS_FIN_WAIT1:
				// If our FIN has been ACKed (perhaps in this segment), then
				// enter TIME-WAIT, start the time-wait timer, turn off the other
				// timers; otherwise enter the CLOSING state.
				// TODO: start time-wait timer if needed
				socket->state = TCPS_CLOSING;
				break;


			case TCPS_FIN_WAIT2:
				socket->state = TCPS_TIME_WAIT;
				// TODO: start time-wait timer
				break;

			case TCPS_TIME_WAIT:
				// TODO: restart 2MSL time-wait
				break;
		}
	}

	return 0;
}
