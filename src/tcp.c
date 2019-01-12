#include <pthread.h>
#include "tcp.h"


extern int RUNNING;
uint32_t timer_ticks;  // in MS
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

uint32_t tcp_timer_get_ticks() {
	return timer_ticks;
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

			// Check if RTO expired
			if(tcp_socket->rto_expires && tcp_socket->rto_expires < timer_ticks) {
				tcp_socket->rto = min(tcp_socket->rto * 2, TCP_RTO_MAX);
				tcp_socket->rto_expires = timer_ticks + tcp_socket->rto;

				printf("Resending segment, RTO=%u\n", tcp_socket->rto);
				tcp_out_queue_send(tcp_socket, 1);
			}
		}

		timer_ticks += TCP_T_SLOW_INTERVAL;

		pthread_mutex_unlock(threads_mutex);

		usleep(TCP_T_SLOW_INTERVAL * 1000);
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

		usleep(TCP_T_FAST_INTERVAL * 1000);
	}
	return NULL;
}

void tcp_calc_rto(struct tcp_socket *tcp_socket) {
	// RFC6298
	int32_t r = tcp_timer_get_ticks() - (tcp_socket->rto_expires - tcp_socket->rto);

	if(tcp_socket->srtt == 0) {
		// First measurement
		tcp_socket->srtt = r;
		tcp_socket->rttvar = r / 2;
	}
	else {
		tcp_socket->rttvar = (int32_t)(((1 - TCP_RTO_BETA) * tcp_socket->rttvar) + TCP_RTO_BETA * abs(tcp_socket->srtt - r));
		tcp_socket->srtt = (int32_t)((1 - TCP_RTO_ALPHA) * tcp_socket->srtt + (TCP_RTO_ALPHA * r));
	}

	int32_t k = 4 * tcp_socket->rttvar;

	tcp_socket->rto = (uint32_t)(tcp_socket->srtt + (max(k, TCP_RTO_CLOCK_GRANUALITY)));
	tcp_socket->rto = max(tcp_socket->rto, TCP_RTO_MIN);

	printf("Using RTO of %u\n", tcp_socket->rto);
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
	tcp_socket->rto = 1000;  // RFC6298: 1 second or greater first
	tcp_socket->iss = (uint32_t)lrand48();
	tcp_socket->snd_nxt = tcp_socket->iss;
	tcp_socket->snd_una = tcp_socket->iss;
	tcp_socket->rcv_wnd = TCP_START_WINDOW_SIZE;

	tcp_socket->sock.protocol = IPPROTO_TCP;
	tcp_socket->sock.source_ip = source_ip;
	tcp_socket->sock.dest_ip = dest_ip;
	tcp_socket->sock.source_port = source_port;
	tcp_socket->sock.dest_port = dest_port;

	tcp_socket->write_queue.list.next = tcp_socket->write_queue.list.prev = &tcp_socket->write_queue.list;
	tcp_socket->read_queue.list.next = tcp_socket->read_queue.list.prev = &tcp_socket->read_queue.list;

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