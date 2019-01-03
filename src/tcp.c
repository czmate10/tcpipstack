#include "tcp.h"


uint16_t tcp_checksum(struct tcp_packet *tcp_pck, uint16_t tcp_len, uint32_t source_ip, uint32_t dest_ip) {
	// We need to include the pseudo-header in the checksum.
	uint32_t sum = htons(IPPROTO_TCP)
				   + htons(tcp_len)
				   + source_ip
				   + dest_ip;

	tcp_pck->checksum = 0;
	return checksum((uint16_t *)tcp_pck, (uint32_t) (tcp_len), sum);
}

void tcp_timer_slow() {

}


void tcp_socket_free(struct tcp_socket *tcp_sck) {
	if(tcp_sck == tcp_sockets_head) {
		if(tcp_sck->next == tcp_sck) {  // This is the only socket
			free(tcp_sck);
			tcp_sockets_head = NULL;
			return;
		}
		else
			tcp_sockets_head = tcp_sck->next;
	}

	struct tcp_socket *prev = tcp_sck->prev;
	struct tcp_socket *next = tcp_sck->next;
	prev->next = next;
	next->prev = prev;

	free(tcp_sck);
}

struct tcp_socket* tcp_socket_new(uint32_t source_ip, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port) {
	struct tcp_socket* tcp_sck = (struct tcp_socket*)malloc(sizeof(struct tcp_socket));
	if(tcp_sck == NULL) {
		perror("could not allocate memory for TCP socket");
		exit(1);
	}

	memset(tcp_sck, 0, sizeof(struct tcp_socket));

	tcp_sck->sock.protocol = IPPROTO_TCP;
	tcp_sck->sock.source_ip = source_ip;
	tcp_sck->sock.dest_ip = dest_ip;
	tcp_sck->sock.source_port = source_port;
	tcp_sck->sock.dest_port = dest_port;

	if(tcp_sockets_head == NULL) {
		tcp_sockets_head = tcp_sck;
		tcp_sck->prev = tcp_sck;
		tcp_sck->next = tcp_sck;
		return tcp_sck;
	}

	// Add to tail
	tcp_sockets_head->prev->next = tcp_sck;
	tcp_sck->prev = tcp_sockets_head->prev;
	tcp_sck->next = tcp_sockets_head;
	tcp_sockets_head->prev = tcp_sck;

	return tcp_sck;
}

struct tcp_socket* tcp_socket_get(uint32_t source_ip, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port) {
	if(tcp_sockets_head == NULL)
		return NULL;

	struct tcp_socket *temp = tcp_sockets_head;
	do {
		if (temp->sock.source_ip == source_ip && temp->sock.dest_ip == dest_ip &&
			temp->sock.source_port == source_port && temp->sock.dest_port == dest_port)
			return temp;
		else
			temp = temp->next;
	} while(temp != tcp_sockets_head);

	return NULL;
}