#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <time.h>
#include <pthread.h>
#include <poll.h>
#include <errno.h>

#include "tap.h"
#include "eth.h"
#include "arp.h"
#include "ipv4.h"
#include "tcp.h"


#define POLL_RATE_NS 1

#define THREAD_COUNT 3
#define THREAD_MAIN 0
#define THREAD_TCP_SLOW 1
#define THREAD_TCP_FAST 2


int RUNNING = 1;
struct net_dev* device = NULL;
pthread_t threads[THREAD_COUNT];
pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;


int handle_eth_frame(struct net_dev *dev, struct eth_frame *eth_frame) {
	if(eth_frame->eth_type == ETH_P_ARP) {
		return arp_process_packet(dev, eth_frame);
	}

	else if(eth_frame->eth_type == ETH_P_IP) {
		return ipv4_process_packet(dev, eth_frame);
	}

	else if(eth_frame->eth_type == ETH_P_IPV6)
		return -1;

	else {
		printf("unknown Ethernet type: %d\n", eth_frame->eth_type);
		return -1;
	}
}

void *main_loop(void *args) {
	pthread_mutex_t *threads_mutex = (pthread_mutex_t *)args;

	struct pollfd poll_fd = { .fd = device->sock_fd, .events = POLLIN | POLLNVAL | POLLERR | POLLHUP };
	struct timespec poll_interval = { .tv_sec = 0, .tv_nsec = POLL_RATE_NS };

	while(RUNNING) {
		int res = ppoll(&poll_fd, 1, &poll_interval, NULL);
		if(res < 0) {
			perror("main loop: poll error");
			break;
		}

		if(poll_fd.revents & POLLIN) {
			struct eth_frame *eth_frame = malloc(ETHERNET_MAX_SIZE);
			if(eth_frame == NULL) {
				perror("could not allocate memory for ethernet frame");
				exit(1);
			}
			memset(eth_frame, 0, ETHERNET_MAX_SIZE);

			uint16_t num_bytes = eth_read(device, eth_frame);
			pthread_mutex_lock(threads_mutex);
			handle_eth_frame(device, eth_frame);
			pthread_mutex_unlock(threads_mutex);

			free(eth_frame);
		}
		else if(poll_fd.revents & POLLNVAL || poll_fd.revents & POLLERR || poll_fd.revents & POLLHUP)
			break;
	}

	return NULL;
}

void create_thread(int id, void *(*func) (void *) ) {
	int res = pthread_create(&threads[id], NULL, (void*)func, (void*)&threads_mutex);
	if(res != 0) {
		fprintf(stderr, "failed to create thread #%d: %s", id, strerror(errno));
		perror("Failed to create thread");
		exit(1);
	}
}

void setup() {
	// TAP device
	char dev_name[IFNAMSIZ];
	strcpy(dev_name, "tap0");
	device = init_tap_device(dev_name);
	if(device == NULL) {
		printf("Failed to create TAP device, exiting...\n");
		exit(1);
	}
	printf("Using TAP device %s\n", dev_name);

	// Main thread
	create_thread(THREAD_MAIN, main_loop);
	create_thread(THREAD_TCP_SLOW, tcp_timer_slow);
	create_thread(THREAD_TCP_FAST, tcp_timer_fast);

	printf("Created threads\n\n");
}

void finish() {
	RUNNING = 0;

	free_tap_device();
	for(int i = 0; i < THREAD_COUNT; i++) {
		pthread_join(threads[i], NULL);
	}
}


#define TEST_SOCKET_POLL_INTERVAL 20  // check if we are connected every 20 ms
#define TEST_SOCKET_TIMEOUT 5000  // timeout in 5 seconds if we are still not connected

struct tcp_socket *test_connect() {
	uint32_t dest_ip;
	inet_pton(AF_INET, "10.0.0.5", &dest_ip);

	srand48(time(NULL));
	uint16_t port = (uint16_t)lrand48();

	pthread_mutex_lock(&threads_mutex);
	struct tcp_socket *tcp_socket = tcp_socket_new(device->ipv4, dest_ip, port, 80);
	tcp_socket->sock.dev = device;
	tcp_out_syn(tcp_socket);
	pthread_mutex_unlock(&threads_mutex);

	uint32_t ticks = 0;
	while(1) {
		if(tcp_socket->state == TCPS_ESTABLISHED) {
			return tcp_socket;
		}

		if(ticks > TEST_SOCKET_TIMEOUT / TEST_SOCKET_POLL_INTERVAL)
			break;

		ticks++;
		usleep(TEST_SOCKET_POLL_INTERVAL * 1000);
	}

	pthread_mutex_lock(&threads_mutex);
	tcp_socket_free(tcp_socket);
	pthread_mutex_unlock(&threads_mutex);
	return NULL;
}

int test_send(struct tcp_socket *tcp_socket, uint8_t *data, size_t data_len) {
	tcp_out_data(tcp_socket, data, (uint16_t)data_len);
	return 0;
}

int main() {
	setup();

	getchar();
	getchar();

	// test tcp_socket
	struct tcp_socket * tcp_socket = test_connect();

	if(tcp_socket) {
		printf("Connected!\n");
		char *test_data = "GET / HTTP/1.1\r\n\r\n";
		test_send(tcp_socket, (uint8_t *) test_data, strlen(test_data));

		while(1) {
			if(tcp_socket->state == TCPS_CLOSED)  // TODO: Socket is more than likely already free'd here
				break;

			usleep(TEST_SOCKET_POLL_INTERVAL * 1000);
		}

		usleep(600 * 1000);  // Wait before closing
		finish();
	}
	else {
		printf("Could not connect!\n");
		finish();
	}

}