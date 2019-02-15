#include <netinet/ip.h>
#include <pthread.h>
#include "tcp.h"


extern int RUNNING;
uint32_t timer_ticks;  // time elapsed since start in MS


uint32_t tcp_timer_get_ticks() {
	return timer_ticks;
}

void *tcp_timer_fast(void *args) {
	pthread_mutex_t *threads_mutex = (pthread_mutex_t *)args;

	while(RUNNING) {
		pthread_mutex_lock(threads_mutex);

		struct list_head *list_item;
		struct tcp_socket *tcp_socket;

		list_for_each(list_item, &tcp_socket_list) {
			tcp_socket = list_entry(list_item, struct tcp_socket, list);

			if(tcp_socket == NULL || tcp_socket->state != TCPS_ESTABLISHED)
				continue;

			if(tcp_socket->delayed_ack)
				tcp_out_ack(tcp_socket);
		}

		timer_ticks += TCP_T_FAST_INTERVAL;

		pthread_mutex_unlock(threads_mutex);

		usleep(TCP_T_FAST_INTERVAL * 1000);
	}
	return NULL;
}

void *tcp_timer_slow(void *args) {
	pthread_mutex_t *threads_mutex = (pthread_mutex_t *)args;

	while(RUNNING) {
		pthread_mutex_lock(threads_mutex);

		struct list_head *list_item;
		struct tcp_socket *tcp_socket;

		list_for_each(list_item, &tcp_socket_list) {
			tcp_socket = list_entry(list_item, struct tcp_socket, list);

			if(tcp_socket == NULL || tcp_socket->state != TCPS_ESTABLISHED)
				continue;

			// Check if RTO expired
			if(tcp_socket->rto_expires && tcp_socket->rto_expires < timer_ticks) {
				tcp_socket->rto = min(tcp_socket->rto * 2, TCP_RTO_MAX);
				tcp_socket->rto_expires = timer_ticks + tcp_socket->rto;

				printf("Resending segment, RTO=%u\n", tcp_socket->rto);
				tcp_out_queue_pop(tcp_socket);
			}
		}

		pthread_mutex_unlock(threads_mutex);

		usleep(TCP_T_SLOW_INTERVAL * 1000);
	}
	return NULL;
}

void tcp_calc_rto(struct tcp_socket *tcp_socket) {
	// RFC6298
	// TODO: implement Karn's algorithm to ignore retransmitted segments when calculating RTO

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
