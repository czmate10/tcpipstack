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

void *main_loop() {
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

			uint16_t num_bytes = eth_read(device, eth_frame);
			handle_eth_frame(device, eth_frame);

			free(eth_frame);
		}
		else if(poll_fd.revents & POLLNVAL || poll_fd.revents & POLLERR || poll_fd.revents & POLLHUP)
			break;
	}

	return NULL;
}

void create_thread(int id, void *(*func) (void *) ) {
	int res = pthread_create(&threads[id], NULL, func, NULL);
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

struct tcp_socket * setup_test_socket() {
	uint32_t dest_ip;
	inet_pton(AF_INET, "10.0.0.5", &dest_ip);

	srand48(time(NULL));
	uint16_t port = (uint16_t)lrand48();
	printf("Using port %u\n\n", port);

	struct tcp_socket *socket = tcp_socket_new(device->ipv4, dest_ip, port, 86);
	socket->sock.dev = device;
	socket->mss = 1460;
	tcp_out_syn(socket);

	return socket;
}

int main() {
	setup();

	// test socket
	struct tcp_socket * socket = setup_test_socket();

	getchar();  // shut down on input
	printf("Shutting down...\n");

	getchar();
	getchar();

	finish();
	tcp_socket_free(socket);
}