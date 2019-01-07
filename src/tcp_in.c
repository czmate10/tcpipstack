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
		uint8_t kind = *ptr;
		switch(kind) {
			case TCP_OPTIONS_END:
				return;

			case TCP_OPTIONS_NOOP:
				ptr++;
				break;

			case TCP_OPTIONS_MSS: {
				opts->mss = ptr[2] << 8 | ptr[3];
				ptr += 4;
				break;
			}

			case TCP_OPTIONS_WSCALE: {
				opts->window_scale = ptr[2];
				ptr += 3;
				break;
			}

			case TCP_OPTIONS_SACK: {
				// TODO
				fprintf(stderr, "sack not implemented");
				exit(1);
			}

			case TCP_OPTIONS_TIMESTAMP: {
				opts->timestamp = ntohl(ptr[2] << 24 | ptr[3] << 16 | ptr[4] << 8 | ptr[5]);
				opts->echo = ntohl(ptr[6] << 24 | ptr[7] << 16 | ptr[8] << 8 | ptr[9]);
				ptr += 10;
				break;
			}

			case TCP_OPTIONS_SACK_PERMITTED: {
				opts->sack_permitted = 1;
				ptr += 2;
				break;
			}

			default: {
				fprintf(stderr, "unknown TCP option encountered: %d, size: %d", *ptr, size);
				exit(1);
			}
		}
	}
}

void tcp_process_syn_sent(struct tcp_socket *socket, struct tcp_segment *tcp_segment, struct tcp_options *opts) {
	// 1: check ACK
	if(tcp_segment->ack) {
		if (tcp_segment->ack_seq <= socket->iss || tcp_segment->ack_seq > socket->snd_nxt) {
			return; // TODO: check RST flag
		}

		if (tcp_segment->ack_seq < socket->snd_una || tcp_segment->ack_seq > socket->snd_nxt) {
			return;
		}
	}

	// 2: check RST bit
	if (tcp_segment->rst) {
		fprintf(stderr, "error: connection reset");
		tcp_socket_free(socket);
		return;
	}

	// TODO: 3: check security

	// 4: check the SYN bit
	if(tcp_segment->syn) {
		socket->rcv_nxt = tcp_segment->seq + 1;
		socket->irs = tcp_segment->seq;
		if(tcp_segment->ack) {
			socket->snd_una = tcp_segment->ack_seq;
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

void tcp_process_listen(struct tcp_socket *socket, struct tcp_segment *tcp_segment, struct tcp_options *opts) {
}

void tcp_process_closed(struct tcp_socket *socket, struct tcp_segment *tcp_segment, struct tcp_options *opts, uint16_t tcp_segment_size) {
	if(tcp_segment->rst)
		return;

	// Send RST
	if(tcp_segment->ack) {
		socket->snd_nxt = tcp_segment->ack_seq;
		tcp_out_rst(socket);
	}
	else {
		socket->rcv_nxt = tcp_segment->seq + tcp_segment_size;
		socket->snd_nxt = 0;
		tcp_out_rstack(socket);
	}
}

int tcp_accept_test(struct tcp_socket *socket, struct tcp_segment *tcp_segment, uint16_t tcp_segment_size) {
	if(tcp_segment_size == 0 && socket->rcv_wnd == 0) {
		return tcp_segment->seq == socket->rcv_nxt;
	}

	else if(tcp_segment_size == 0 && socket->rcv_wnd > 0)
		return socket->rcv_nxt <= tcp_segment->seq < (socket->rcv_nxt + socket->rcv_wnd);

	else if(tcp_segment_size > 0 && socket->rcv_wnd == 0)
		return 0;

	else if(tcp_segment_size > 0 && socket->rcv_wnd > 0)
		return ((socket->rcv_nxt <= tcp_segment->seq < socket->rcv_nxt+socket->rcv_wnd) ||
				(socket->rcv_nxt <= tcp_segment->seq + tcp_segment_size - 1 < socket->rcv_nxt+socket->rcv_wnd));

	return 0;
}

uint8_t tcp_process_options(struct tcp_segment *tcp_segment, struct tcp_options *opts) {
	uint8_t options_size = (uint8_t) ((tcp_segment->data_offset - 5) << 4);
	if (options_size > 0)
		tcp_parse_options(opts, tcp_segment->data, options_size);
	else
		opts->mss = TCP_DEFAULT_MSS;

	return options_size;
}

void tcp_process_segment(struct net_dev *dev, struct eth_frame *frame) {
	struct ipv4_packet *ip_packet = (struct ipv4_packet *) frame->payload;
	struct tcp_segment *tcp_segment = (struct tcp_segment *) (ip_packet->data +
														((ip_packet->header_len * 4) - sizeof(struct ipv4_packet)));

	uint16_t checksum = tcp_segment->checksum;
	uint16_t tcp_segment_size = (uint16_t)(ip_packet->len - ip_packet->header_len * 4);
	uint16_t tcp_data_size = (uint16_t)(tcp_segment_size - TCP_HEADER_SIZE);

	// Compare checksums
	if (checksum != tcp_checksum(tcp_segment, tcp_segment_size, ip_packet->source_ip, ip_packet->dest_ip)) {
		fprintf(stderr, "TCP segment has mismatching checksum!\n");
		return;
	}

	// ntoh
	tcp_segment_ntoh(tcp_segment);

	// Get socket
	struct tcp_socket *socket = tcp_socket_get(ip_packet->dest_ip, ip_packet->source_ip, tcp_segment->dest_port,
											   tcp_segment->source_port);
	if (!socket || socket->state == TCPS_CLOSED) {
		// TODO: If there is no RST flag present, send RST
		printf("TCP segment dropped (no active connection): %d -> %d\n", tcp_segment->source_port, tcp_segment->dest_port);
		return;
	}

	// Debug print
	printf("TCP IN :: %d->%d | FIN %d | SYN %d | RST %d | PSH %d | ACK %d | URG %d | ECE %d | CWR %d | SEQ %u | WS %d | MSS %d\n",
		   tcp_segment->source_port, tcp_segment->dest_port, tcp_segment->fin, tcp_segment->syn, tcp_segment->rst, tcp_segment->psh,
		   tcp_segment->ack, tcp_segment->urg, tcp_segment->ece, tcp_segment->cwr, tcp_segment->seq, tcp_segment->window_size, socket->mss);

	// Get options
	struct tcp_options opts = {0};
	uint8_t options_size = tcp_process_options(tcp_segment, &opts);


	// First check if we are in one of these 3 states
	if(socket->state == TCPS_SYN_SENT) {
		tcp_process_syn_sent(socket, tcp_segment, &opts);
		return;
	}
	else if(socket->state == TCPS_LISTEN) {
		tcp_process_listen(socket, tcp_segment, &opts);
		return;
	}
	else if(socket->state == TCPS_CLOSED) {
		tcp_process_closed(socket, tcp_segment, &opts, tcp_segment_size);
		return;
	}

	// 1: check sequence number
	if(!tcp_accept_test(socket, tcp_segment, tcp_data_size)) {
		fprintf(stderr, "Invalid TCP ack sequence num: %u - sending RST\n", tcp_segment->ack_seq);

		if(!tcp_segment->rst)
			tcp_out_ack(socket);

		return;
	}

	// 2: check the RST bit
	if(tcp_segment->rst) {
		switch(socket->state) {
			case TCPS_SYN_RCVD:
				// If passive open, set to LISTEN stage
				// If active open, connection was refused
				fprintf(stderr, "connection refused\n");
				socket->state = TCPS_CLOSED;  // or LISTEN if passive open
				tcp_socket_free(socket);
				return;

			case TCPS_ESTABLISHED:
			case TCPS_FIN_WAIT1:
			case TCPS_FIN_WAIT2:
			case TCPS_CLOSE_WAIT:
				// TODO: flush segment queues
				fprintf(stderr, "connection reset\n");
				socket->state = TCPS_CLOSED;
				tcp_socket_free(socket);
				return;

			case TCPS_CLOSING:
			case TCPS_LAST_ACK:
			case TCPS_TIME_WAIT:
				socket->state = TCPS_CLOSED;
				tcp_socket_free(socket);
				return;

			default:
				fprintf(stderr, "unknown state for socket: %d\n", socket->state);
				return;
		}
	}

	// 3: check security
	// -----------------

	// 4: check the SYN bit
	if(tcp_segment->syn) {
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
				return;
		}
	}

	// 5: check ACK field
	if(!tcp_segment->ack)
		return;

	switch(socket->state) {
		case TCPS_TIME_WAIT:
			tcp_out_ack(socket);
			// TODO: restart 2MSL timer here
			return;

		case TCPS_LAST_ACK:
			// FIN acknowledged
			tcp_socket_free(socket);
			return;

		case TCPS_SYN_RCVD:
			if(socket->snd_una <= tcp_segment->ack_seq <= socket->snd_nxt) {
				socket->state = TCPS_ESTABLISHED;
				// Continue processing
			}
			else {
				tcp_out_rst(socket);
				return;
			}
		case TCPS_FIN_WAIT1:
			socket->state = TCPS_FIN_WAIT2;
		case TCPS_FIN_WAIT2:
			// close is acknowledged, but don't delete the TCB yet
		case TCPS_CLOSING:
			socket->state = TCPS_TIME_WAIT;
		case TCPS_CLOSE_WAIT:
		case TCPS_ESTABLISHED:
			if(socket->snd_una < tcp_segment->ack_seq <= socket->snd_nxt) {
				socket->snd_una = tcp_segment->ack_seq;
				// TODO: remove acknowledged segments in the buffer

				// Set send window, but not if it's an old segment (snd_wl1, snd_wl2)
				if(socket->snd_wl1 < tcp_segment->seq || (socket->snd_wl1 == tcp_segment->seq && socket->snd_wl2 <= tcp_segment->ack_seq)) {
					socket->snd_wnd = tcp_segment->window_size;
					socket->snd_wl1 = tcp_segment->seq;
					socket->snd_wl2 = tcp_segment->ack_seq;
				}
			}
			else if(tcp_segment->ack_seq > socket->snd_nxt) {
				// Not yet sent
				tcp_out_ack(socket);
				return;
			}
	}

	// 6: check URG bit

	// 7: process segment text
	switch(socket->state) {
		case TCPS_ESTABLISHED:
		case TCPS_FIN_WAIT1:
		case TCPS_FIN_WAIT2: {
			uint16_t payload_size = ip_packet->len - sizeof(struct ipv4_packet) - sizeof(struct tcp_segment) - options_size;

			if (tcp_segment->psh && payload_size > 0) {
				// Get payload
				uint8_t *payload = tcp_segment->data + options_size;

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
			return;
	}

	// 8: check FIN bit
	if(tcp_segment->fin) {
		switch (socket->state) {
			case TCPS_CLOSED:
			case TCPS_LISTEN:
			case TCPS_SYN_SENT:
				// SEG.SEQ cannot be validated; drop the segment
				return;

			case TCPS_SYN_RCVD:
			case TCPS_ESTABLISHED:
				printf("TCP :: closing connection\n");

				socket->rcv_nxt = tcp_segment->seq+1;
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
}
