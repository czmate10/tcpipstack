#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "ipv4.h"
#include "tcp.h"
#include "utils.h"


uint8_t tcp_in_options(struct tcp_segment *tcp_segment, struct tcp_options *opts) {
	uint8_t options_size = (uint8_t) ((tcp_segment->data_offset - 5) << 2);
	if (options_size == 0)
		return options_size;

	uint8_t* ptr = tcp_segment->data;
	while(ptr < tcp_segment->data + options_size) {
		uint8_t kind = *ptr;
		switch(kind) {
			case TCP_OPTIONS_END:
				return options_size;

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
				fprintf(stderr, "sack not implemented\n");
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
				fprintf(stderr, "unknown TCP option encountered: %d, size: %d\n", *ptr, options_size);
				exit(1);
			}
		}
	}

	return options_size;
}

void tcp_in_syn_sent(struct tcp_socket *tcp_socket, struct tcp_segment *tcp_segment, struct tcp_options *opts) {
	// 1: check ACK
	if(tcp_segment->ack) {
		if (tcp_segment->ack_seq <= tcp_socket->iss || tcp_segment->ack_seq > tcp_socket->snd_nxt) {
			if(!tcp_segment->rst)
				tcp_out_rst(tcp_socket);

			return;
		}

		if (tcp_segment->ack_seq < tcp_socket->snd_una || tcp_segment->ack_seq > tcp_socket->snd_nxt) {
			return;
		}
	}

	// 2: check RST bit
	if (tcp_segment->rst) {
		fprintf(stderr, "error: connection reset\n");
		tcp_socket_free(tcp_socket);
		return;
	}

	// TODO: 3: check security

	// 4: check the SYN bit
	if(tcp_segment->syn) {
		tcp_socket->rcv_nxt = tcp_segment->seq + 1;
		tcp_socket->irs = tcp_segment->seq;

		// Set MSS
		tcp_socket->mss = min(tcp_socket->mss, opts->mss);

		// Set slow start window size - see RFC5681 3.1
		if(tcp_socket->mss > 2190)
			tcp_socket->cwnd = (uint32_t)(tcp_socket->mss * 2);
		else if(tcp_socket->mss > 1095)
			tcp_socket->cwnd = (uint32_t)(tcp_socket->mss * 3);
		else
			tcp_socket->cwnd = (uint32_t)(tcp_socket->mss * 4);

		if(tcp_segment->ack) {
			tcp_socket->snd_una = tcp_segment->ack_seq;
			// remove SYN segment from retransmission queue
			tcp_out_queue_clear(tcp_socket, tcp_socket->snd_una);
		}

		if(tcp_socket->snd_una > tcp_socket->iss) {
			// Our SYN has been ACKed
			tcp_socket->state = TCPS_ESTABLISHED;
			tcp_out_ack(tcp_socket);
		}
		else {
			tcp_socket->state = TCPS_SYN_RCVD;
			tcp_socket->snd_una = tcp_socket->iss;
			tcp_out_synack(tcp_socket);
		}
	}
}

void tcp_in_listen(struct tcp_socket *tcp_socket, struct tcp_segment *tcp_segment, struct tcp_options *opts) {
}

void tcp_in_closed(struct tcp_socket *tcp_socket, struct tcp_segment *tcp_segment, struct tcp_options *opts, uint16_t tcp_segment_size) {
	if(tcp_segment->rst)
		return;

	// Send RST
	if(tcp_segment->ack) {
		tcp_socket->snd_nxt = tcp_segment->ack_seq;
		tcp_out_rst(tcp_socket);
	}
	else {
		tcp_socket->rcv_nxt = tcp_segment->seq + tcp_segment_size;
		tcp_socket->snd_nxt = 0;
		tcp_out_rstack(tcp_socket);
	}
}

int tcp_accept_test(struct tcp_socket *tcp_socket, struct tcp_segment *tcp_segment, uint16_t tcp_segment_size) {
	if(tcp_segment_size == 0 && tcp_socket->rcv_wnd == 0) {
		return tcp_segment->seq == tcp_socket->rcv_nxt;
	}

	else if(tcp_segment_size == 0 && tcp_socket->rcv_wnd > 0)
		return tcp_socket->rcv_nxt <= tcp_segment->seq < (tcp_socket->rcv_nxt + tcp_socket->rcv_wnd);

	else if(tcp_segment_size > 0 && tcp_socket->rcv_wnd == 0)
		return 0;

	else if(tcp_segment_size > 0 && tcp_socket->rcv_wnd > 0)
		return ((tcp_socket->rcv_nxt <= tcp_segment->seq < tcp_socket->rcv_nxt+tcp_socket->rcv_wnd) ||
				(tcp_socket->rcv_nxt <= tcp_segment->seq + tcp_segment_size - 1 < tcp_socket->rcv_nxt+tcp_socket->rcv_wnd));

	return 0;
}

void tcp_in(struct eth_frame *frame) {
	struct ipv4_packet *ip_packet = (struct ipv4_packet *) frame->payload;
	struct tcp_segment *tcp_segment = (struct tcp_segment *) (ip_packet->data +
														((ip_packet->header_len * 4) - sizeof(struct ipv4_packet)));

	uint16_t checksum = tcp_segment->checksum;
	uint16_t tcp_segment_size = (uint16_t)(ip_packet->len - ip_packet->header_len * 4);
	uint16_t tcp_data_size = (uint16_t)(tcp_segment_size - TCP_HEADER_SIZE);

	// Compare checksums
	tcp_segment->checksum = 0;
	if (checksum != tcp_checksum((void *)tcp_segment, tcp_segment_size, ip_packet->source_ip, ip_packet->dest_ip)) {
		fprintf(stderr, "TCP segment has mismatching checksum!\n");
		return;
	}

	// ntoh
	tcp_segment_ntoh(tcp_segment);

	// Get tcp_socket
	struct tcp_socket *tcp_socket = tcp_socket_get(ip_packet->dest_ip, ip_packet->source_ip, tcp_segment->dest_port,
											   tcp_segment->source_port);
	if (!tcp_socket || tcp_socket->state == TCPS_CLOSED) {
		// TODO: If there is no RST flag present, send RST
		printf("TCP segment dropped (no active connection): %d -> %d\n", tcp_segment->source_port, tcp_segment->dest_port);
		return;
	}

	// Debug print
	debug_tcp("TCP IN", tcp_segment, tcp_socket);

	// Get options
	struct tcp_options opts = {0};
	uint8_t options_size = tcp_in_options(tcp_segment, &opts);

	if(opts.mss == 0)  // MSS wasn't supplied
		opts.mss = tcp_socket->mss;


	// First check if we are in one of these 3 states
	if(tcp_socket->state == TCPS_SYN_SENT) {
		tcp_in_syn_sent(tcp_socket, tcp_segment, &opts);
		if(tcp_socket->state != TCPS_ESTABLISHED)  // if ACK segment was valid, continue processing
			return;
		else
			goto check_urg;
	}
	else if(tcp_socket->state == TCPS_LISTEN) {
		tcp_in_listen(tcp_socket, tcp_segment, &opts);
		return;
	}
	else if(tcp_socket->state == TCPS_CLOSED) {
		tcp_in_closed(tcp_socket, tcp_segment, &opts, tcp_segment_size);
		return;
	}

	// 1: check sequence number
	if(!tcp_accept_test(tcp_socket, tcp_segment, tcp_data_size)) {
		fprintf(stderr, "Invalid TCP ack sequence num: %u - sending ACK\n", tcp_segment->ack_seq);

		if(!tcp_segment->rst)
			tcp_out_ack(tcp_socket);

		return;
	}

	// 2: check the RST bit
	if(tcp_segment->rst) {
		switch(tcp_socket->state) {
			case TCPS_SYN_RCVD:
				// If passive open, set to LISTEN stage
				// If active open, connection was refused
				fprintf(stderr, "connection refused\n");
				tcp_socket->state = TCPS_CLOSED;  // or LISTEN if passive open
				tcp_socket_free(tcp_socket);
				return;

			case TCPS_ESTABLISHED:
			case TCPS_FIN_WAIT1:
			case TCPS_FIN_WAIT2:
			case TCPS_CLOSE_WAIT:
				fprintf(stderr, "connection reset\n");
				tcp_socket->state = TCPS_CLOSED;
				tcp_socket_free(tcp_socket);
				return;

			case TCPS_CLOSING:
			case TCPS_LAST_ACK:
			case TCPS_TIME_WAIT:
				tcp_socket->state = TCPS_CLOSED;
				tcp_socket_free(tcp_socket);
				return;

			default:
				fprintf(stderr, "unknown state for tcp_socket: %d\n", tcp_socket->state);
				return;
		}
	}

	// 3: check security
	// -----------------

	// 4: check the SYN bit
	if(tcp_segment->syn) {
		switch(tcp_socket->state) {
			case TCPS_SYN_RCVD:
			case TCPS_ESTABLISHED:
			case TCPS_FIN_WAIT1:
			case TCPS_FIN_WAIT2:
			case TCPS_CLOSE_WAIT:
			case TCPS_CLOSING:
			case TCPS_LAST_ACK:
			case TCPS_TIME_WAIT:
				fprintf(stderr, "connection reset\n");
				tcp_out_rst(tcp_socket);
				tcp_socket->state = TCPS_CLOSED;
				tcp_socket_free(tcp_socket);
				return;
			default:
				break;
		}
	}

	// 5: check ACK field
	if(!tcp_segment->ack)
		return;

	switch(tcp_socket->state) {
		case TCPS_TIME_WAIT:
			tcp_out_ack(tcp_socket);
			// TODO: restart 2MSL timer here
			return;

		case TCPS_LAST_ACK:
			// FIN acknowledged
			printf("TCP :: closed connection\n");
			tcp_socket->state = TCPS_CLOSED;
			tcp_socket_free(tcp_socket);
			return;

		case TCPS_SYN_RCVD:
			if(tcp_socket->snd_una <= tcp_segment->ack_seq <= tcp_socket->snd_nxt) {
				tcp_socket->state = TCPS_ESTABLISHED;
				// Continue processing
			}
			else {
				tcp_out_rst(tcp_socket);
				return;
			}
		case TCPS_FIN_WAIT1:
			tcp_socket->state = TCPS_FIN_WAIT2;
		case TCPS_FIN_WAIT2:
			// close is acknowledged, but don't delete the TCB yet
		case TCPS_CLOSING:
			tcp_socket->state = TCPS_TIME_WAIT;
		case TCPS_CLOSE_WAIT:
		case TCPS_ESTABLISHED:
			if(tcp_socket->snd_una < tcp_segment->ack_seq <= tcp_socket->snd_nxt) {
				tcp_socket->snd_una = tcp_segment->ack_seq;
				tcp_out_queue_clear(tcp_socket, tcp_socket->snd_una);  // Clear write queue
				tcp_socket->rto_expires = tcp_timer_get_ticks() + tcp_socket->rto;  // Restart RTO timer

				// Set send window, but not if it's an old segment (snd_wl1, snd_wl2)
				if(tcp_socket->snd_wl1 < tcp_segment->seq || (tcp_socket->snd_wl1 == tcp_segment->seq && tcp_socket->snd_wl2 <= tcp_segment->ack_seq)) {
					tcp_socket->snd_wnd = tcp_segment->window_size;
					tcp_socket->snd_wl1 = tcp_segment->seq;
					tcp_socket->snd_wl2 = tcp_segment->ack_seq;
				}
			}
			else if(tcp_segment->ack_seq > tcp_socket->snd_nxt) {
				// Not yet sent
				tcp_out_ack(tcp_socket);
				return;
			}
		default:
			break;
	}

	// 6: check URG bit
check_urg:


	// 7: process segment text
	switch(tcp_socket->state) {
		case TCPS_ESTABLISHED:
		case TCPS_FIN_WAIT1:
		case TCPS_FIN_WAIT2: {
			uint16_t payload_size = ip_packet->len - sizeof(struct ipv4_packet) - sizeof(struct tcp_segment) - options_size;

			if (payload_size > 0) {
				// Get payload
				uint8_t *payload = tcp_segment->data + options_size;

				// Set rcv_next
				tcp_socket->rcv_nxt = tcp_segment->seq + payload_size + (tcp_segment->fin & 0x01);  // add 1 to ack if the segment is also FIN

				// Debug print
//				printf("\nReceived (%d bytes):\n--------------------\n%.*s\n--------------------\n",
//					   payload_size, payload_size, payload);

				if(tcp_socket->delayed_ack)  // RFC1122 states there should be ACK for at least every 2nd incoming segment
					tcp_out_ack(tcp_socket);
				else
					tcp_socket->delayed_ack = 1;
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
			break;
	}

	// 8: check FIN bit
	if(tcp_segment->fin) {
		switch (tcp_socket->state) {
			case TCPS_CLOSED:
			case TCPS_LISTEN:
			case TCPS_SYN_SENT:
				// SEG.SEQ cannot be validated; drop the segment
				return;

			case TCPS_SYN_RCVD:
			case TCPS_ESTABLISHED:
				printf("TCP :: closing connection...\n");

				// Flush segment queues
				tcp_socket_free_queues(tcp_socket);

				if(!tcp_segment->psh) {
					// We already sent ACK for PSH
					tcp_socket->rcv_nxt = tcp_segment->seq + 1;
					tcp_out_ack(tcp_socket);
				}

				tcp_socket->state = TCPS_CLOSE_WAIT;

				// TODO: send close to application
				tcp_out_fin(tcp_socket);
				tcp_socket->state = TCPS_LAST_ACK;
				break;

			case TCPS_FIN_WAIT1:
				// If our FIN has been ACKed (perhaps in this segment), then
				// enter TIME-WAIT, start the time-wait timer, turn off the other
				// timers; otherwise enter the CLOSING state.
				// TODO: start time-wait timer if needed
				tcp_socket->state = TCPS_CLOSING;
				break;


			case TCPS_FIN_WAIT2:
				tcp_socket->state = TCPS_TIME_WAIT;
				// TODO: start time-wait timer
				break;

			case TCPS_TIME_WAIT:
				// TODO: restart 2MSL time-wait
				break;

			default:
				break;
		}
	}
}
