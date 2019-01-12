#include <pthread.h>
#include "tcp.h"


extern int RUNNING;
static LIST_HEAD(tcp_socket_list);


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

		struct list_head *list_item;
		struct tcp_socket *tcp_socket;

		list_for_each(list_item, &tcp_socket_list) {
			tcp_socket = list_entry(list_item, struct tcp_socket, list);

			if(tcp_socket == NULL)
				break;

		}

		pthread_mutex_unlock(threads_mutex);

		usleep(TCP_T_SLOW_INTERVAL);
	}
	return NULL;
}

void *tcp_timer_fast(void *args) {
	pthread_mutex_t *threads_mutex = (pthread_mutex_t *)args;

	while(RUNNING) {
		pthread_mutex_lock(threads_mutex);

		struct list_head *list_item;
		struct tcp_socket *tcp_socket;

		list_for_each(list_item, &tcp_socket_list) {
			tcp_socket = list_entry(list_item, struct tcp_socket, list);

			if(tcp_socket == NULL)
				break;

			if(tcp_socket->delayed_ack)
				tcp_out_ack(tcp_socket);
		}

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

	list_del(&tcp_socket->list);
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

	list_add(&tcp_socket->list, &tcp_socket_list);

	return tcp_socket;
}

struct tcp_socket* tcp_socket_get(uint32_t source_ip, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port) {
	struct list_head *list_item;
	struct tcp_socket *tcp_socket_item;

	list_for_each(list_item, &tcp_socket_list) {
		tcp_socket_item = list_entry(list_item, struct tcp_socket, list);

		if(tcp_socket_item == NULL)
			return NULL;

		if(tcp_socket_item->sock.source_ip == source_ip && tcp_socket_item->sock.dest_ip == dest_ip &&
				tcp_socket_item->sock.source_port == source_port && tcp_socket_item->sock.dest_port == dest_port) {
			return tcp_socket_item;
		}
	}

	return NULL;
}