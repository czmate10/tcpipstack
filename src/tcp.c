#include <pthread.h>
#include "tcp.h"

extern int RUNNING;

uint16_t tcp_checksum(struct tcp_segment *tcp_segment, uint16_t tcp_segment_len, uint32_t source_ip, uint32_t dest_ip) {
	// We need to include the pseudo-header in the checksum.
	uint32_t sum = htons(IPPROTO_TCP)
				   + htons(tcp_segment_len)
				   + source_ip
				   + dest_ip;

	tcp_segment->checksum = 0;
	return checksum((uint16_t *)tcp_segment, (uint32_t) (tcp_segment_len), sum);
}

void *tcp_timer_slow(void *args) {
	pthread_mutex_t *threads_mutex = (pthread_mutex_t *)args;

	while(RUNNING) {
		pthread_mutex_lock(threads_mutex);

		struct tcp_socket *tcp_socket = tcp_sockets_head;
		if(tcp_socket == NULL)
			continue;

		do {

		} while(tcp_socket != tcp_sockets_head);

		pthread_mutex_unlock(threads_mutex);

		usleep(TCP_T_SLOW_INTERVAL);
	}
	return NULL;
}

void *tcp_timer_fast(void *args) {
	pthread_mutex_t *threads_mutex = (pthread_mutex_t *)args;

	while(RUNNING) {
		pthread_mutex_lock(threads_mutex);

		struct tcp_socket *tcp_socket = tcp_sockets_head;
		if(tcp_socket == NULL)
			continue;

		do {
			if(tcp_socket->delayed_ack) {
				tcp_socket->delayed_ack = 0;
				tcp_out_ack(tcp_socket);
			}
		} while(tcp_socket != tcp_sockets_head);

		pthread_mutex_unlock(threads_mutex);

		usleep(TCP_T_FAST_INTERVAL);
	}
	return NULL;
}

void tcp_socket_wait_2msl(struct tcp_socket *tcp_socket) {
	// TODO: actually wait 2msl
	tcp_socket_free(tcp_socket);
}

void tcp_socket_free(struct tcp_socket *tcp_socket) {
	if(tcp_socket == NULL)
		return;

	if(tcp_socket == tcp_sockets_head) {
		if(tcp_socket->next == tcp_socket) {  // This is the only socket
			free(tcp_socket);
			tcp_sockets_head = NULL;
			return;
		}
		else
			tcp_sockets_head = tcp_socket->next;
	}

	struct tcp_socket *prev = tcp_socket->prev;
	struct tcp_socket *next = tcp_socket->next;
	prev->next = next;
	next->prev = prev;

	free(tcp_socket);
}

struct tcp_socket* tcp_socket_new(uint32_t source_ip, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port) {
	struct tcp_socket* tcp_socket = (struct tcp_socket*)malloc(sizeof(struct tcp_socket));
	if(tcp_socket == NULL) {
		perror("could not allocate memory for TCP socket");
		exit(1);
	}
	memset(tcp_socket, 0, sizeof(struct tcp_socket));

	tcp_socket->state = TCPS_CLOSED;
	tcp_socket->iss = (uint32_t)lrand48();
	tcp_socket->snd_nxt = tcp_socket->iss;
	tcp_socket->snd_una = tcp_socket->iss;
	tcp_socket->rcv_wnd = TCP_START_WINDOW_SIZE;

	tcp_socket->sock.protocol = IPPROTO_TCP;
	tcp_socket->sock.source_ip = source_ip;
	tcp_socket->sock.dest_ip = dest_ip;
	tcp_socket->sock.source_port = source_port;
	tcp_socket->sock.dest_port = dest_port;

	if(tcp_sockets_head == NULL) {
		tcp_sockets_head = tcp_socket;
		tcp_socket->prev = tcp_socket;
		tcp_socket->next = tcp_socket;
		return tcp_socket;
	}

	// Add to tail
	tcp_sockets_head->prev->next = tcp_socket;
	tcp_socket->prev = tcp_sockets_head->prev;
	tcp_socket->next = tcp_sockets_head;
	tcp_sockets_head->prev = tcp_socket;

	return tcp_socket;
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