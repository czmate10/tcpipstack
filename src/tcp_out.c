#include <memory.h>
#include <malloc.h>
#include "tcp.h"
#include "skbuff.h"
#include "ipv4.h"



struct sk_buff *tcp_out_create_buffer(uint16_t payload_size) {
	struct sk_buff *buffer = skb_alloc(ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE + payload_size);
	struct tcp_segment *tcp_segment = tcp_segment_from_skb(buffer);

	tcp_segment->data_offset = TCP_HEADER_SIZE >> 2;

	return buffer;
}


// Calculates seq and ack_seq
void tcp_out_set_seqnums(struct tcp_socket *tcp_socket, struct sk_buff *buffer) {
	struct tcp_segment *tcp_segment = tcp_segment_from_skb(buffer);

	tcp_segment->seq = tcp_socket->snd_nxt;
	tcp_segment->ack_seq = tcp_socket->rcv_nxt;
}


// Converts header variables to network endianness and fills checksum
void tcp_out_header(struct tcp_socket *tcp_socket, struct sk_buff *buffer) {
	struct ipv4_packet *ip_packet = ipv4_packet_from_skb(buffer);
	struct tcp_segment *tcp_segment = tcp_segment_from_skb(buffer);

	ip_packet->protocol = IPPROTO_TCP;

	tcp_segment->seq = htonl(tcp_segment->seq);
	tcp_segment->ack_seq = htonl(tcp_segment->ack_seq);
	tcp_segment->source_port = htons(tcp_socket->sock.source_port);
	tcp_segment->dest_port = htons(tcp_socket->sock.dest_port);
	tcp_segment->window_size = htons((uint16_t)tcp_socket->rcv_wnd);

	tcp_segment->checksum = 0;
	tcp_segment->checksum = tcp_checksum((void *)tcp_segment, (uint16_t)(buffer->size - ETHERNET_HEADER_SIZE - IP_HEADER_SIZE),
										 tcp_socket->sock.source_ip, tcp_socket->sock.dest_ip);
}

// Sends TCP segment
void tcp_out_send(struct tcp_socket *tcp_socket, struct sk_buff *buffer) {
	// Set RTO
	tcp_socket->rto_expires = tcp_timer_get_ticks() + tcp_socket->rto;

	//if(!tcp_segment->psh || tcp_socket->rto > 1000) // for debugging
	ipv4_send_packet(&tcp_socket->sock, buffer);
}


uint32_t tcp_out_data(struct tcp_socket *tcp_socket, uint8_t *data, uint32_t data_len) {
    uint32_t packet_count = data_len / (tcp_socket->mss + 1) + 1;

    for(int i = 0; i < packet_count; i++) {
        uint16_t packet_len = (i < packet_count - 1) ? tcp_socket->mss : (uint16_t)(data_len % tcp_socket->mss);
        struct sk_buff *buffer = tcp_out_create_buffer(packet_len);
        struct tcp_segment *tcp_segment = tcp_segment_from_skb(buffer);

        // Set PSH flag only if last packet
        if(i == packet_count - 1)
            tcp_segment->psh = 1;

        tcp_segment->ack = 1;

        buffer->payload_size = packet_len;

        memcpy(tcp_segment->data, data + (i * tcp_socket->mss), (size_t)packet_len);

		tcp_out_queue_push(tcp_socket, buffer);
    }

	tcp_out_queue_pop(tcp_socket);
	return data_len;
}

void tcp_out_queue_push(struct tcp_socket *tcp_socket, struct sk_buff *sk_buff) {
	struct tcp_buffer_queue_entry *buffer_queue_entry = malloc(sizeof(struct tcp_buffer_queue_entry));
	buffer_queue_entry->next = NULL;
	buffer_queue_entry->sk_buff = sk_buff;

	if(tcp_socket->out_queue_head == NULL)
		tcp_socket->out_queue_head = buffer_queue_entry;
	else {
		struct tcp_buffer_queue_entry *tail = tcp_socket->out_queue_head;
		while(tail->next != NULL)
			tail = tail->next;

		tail->next = buffer_queue_entry;
	}

	sk_buff->manual_free = 1;  // don't free() when calling eth_write()
}

void tcp_out_queue_pop(struct tcp_socket *tcp_socket) {
	struct tcp_buffer_queue_entry *entry = tcp_socket->out_queue_head;

	while(entry != NULL && entry->sk_buff->payload_size < tcp_socket->snd_wnd) {
		tcp_out_set_seqnums(tcp_socket, entry->sk_buff);
		tcp_out_header(tcp_socket, entry->sk_buff);

		tcp_out_send(tcp_socket, entry->sk_buff);
		tcp_socket->snd_nxt += entry->sk_buff->payload_size;
		tcp_socket->snd_wnd -= entry->sk_buff->payload_size;
		tcp_socket->delayed_ack = 0;  // piggyback off

		entry = entry->next;
	}
}

void tcp_out_queue_clear(struct tcp_socket *tcp_socket, uint32_t seq_num) {
	while(tcp_socket->out_queue_head != NULL) {
		if(tcp_socket->snd_nxt + tcp_socket->out_queue_head->sk_buff->payload_size > seq_num)
			break;

		tcp_calc_rto(tcp_socket);

		skb_free(tcp_socket->out_queue_head->sk_buff);

		struct tcp_buffer_queue_entry *buffer_queue_entry_next = tcp_socket->out_queue_head->next;
		free(tcp_socket->out_queue_head);
		tcp_socket->out_queue_head = buffer_queue_entry_next;
	}

	// No more unacknowledged packets?
	if(tcp_socket->out_queue_head == NULL) {
		tcp_socket->rto_expires = 0;
	}
}

void tcp_out_ack(struct tcp_socket *tcp_socket) {
	struct sk_buff *buffer = tcp_out_create_buffer(0);
	struct tcp_segment *tcp_segment = tcp_segment_from_skb(buffer);

	tcp_segment->ack = 1;
	tcp_out_set_seqnums(tcp_socket, buffer);

	tcp_out_header(tcp_socket, buffer);
	tcp_out_send(tcp_socket, buffer);

	tcp_socket->delayed_ack = 0;
}

void tcp_out_syn(struct tcp_socket *tcp_socket) {
	struct sk_buff *buffer = tcp_out_create_buffer(4);
	struct tcp_segment *tcp_segment = tcp_segment_from_skb(buffer);

	// Set state
	tcp_socket->state = TCPS_SYN_SENT;

	// TCP
	tcp_segment->syn = 1;
	tcp_segment->data_offset = 6;
	tcp_out_set_seqnums(tcp_socket, buffer);

	// Options TODO: improve this part
	uint16_t mss = htons(tcp_socket->mss);
	tcp_segment->data[0] = TCP_OPTIONS_MSS;
	tcp_segment->data[1] = 4;
	memcpy(&tcp_segment->data[2], &mss, 2);

	// Send it
	tcp_out_queue_push(tcp_socket, buffer);
	tcp_out_queue_pop(tcp_socket);

	// Increase SND.NXT by 1
	tcp_socket->snd_nxt++;
}

void tcp_out_fin(struct tcp_socket *tcp_socket) {
	struct sk_buff *buffer = tcp_out_create_buffer(0);
	struct tcp_segment *tcp_segment = tcp_segment_from_skb(buffer);

	tcp_segment->fin = 1;
	tcp_segment->ack = 1;
	tcp_out_set_seqnums(tcp_socket, buffer);

	tcp_out_header(tcp_socket, buffer);
	tcp_out_send(tcp_socket, buffer);
}

void tcp_out_synack(struct tcp_socket *tcp_socket) {
	struct sk_buff *buffer = tcp_out_create_buffer(0);
	struct tcp_segment *tcp_segment = tcp_segment_from_skb(buffer);

	tcp_segment->ack = 0;
	tcp_segment->syn = 1;
	tcp_out_set_seqnums(tcp_socket, buffer);

	tcp_out_header(tcp_socket, buffer);
	tcp_out_send(tcp_socket, buffer);
}

void tcp_out_rst(struct tcp_socket *tcp_socket) {
	struct sk_buff *buffer = tcp_out_create_buffer(0);
	struct tcp_segment *tcp_segment = tcp_segment_from_skb(buffer);

	tcp_segment->rst = 1;
	tcp_out_set_seqnums(tcp_socket, buffer);

	tcp_out_header(tcp_socket, buffer);
	tcp_out_send(tcp_socket, buffer);
}

void tcp_out_rstack(struct tcp_socket *tcp_socket) {
	struct sk_buff *buffer = tcp_out_create_buffer(0);
	struct tcp_segment *tcp_segment = tcp_segment_from_skb(buffer);

	tcp_segment->ack = 1;
	tcp_segment->rst = 1;
	tcp_out_set_seqnums(tcp_socket, buffer);

	tcp_out_header(tcp_socket, buffer);
	tcp_out_send(tcp_socket, buffer);
}
