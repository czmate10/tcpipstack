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

#define __USE_GNU
#include <poll.h>

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
struct netdev* device = NULL;
pthread_t threads[THREAD_COUNT];


int handle_eth_packet(struct netdev* dev, struct eth_frame *eth_frame) {
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
				perror("could not allocate memory for ethernet packet");
				exit(1);
			}

			uint16_t num_bytes = eth_read(device, eth_frame);
			handle_eth_packet(device, eth_frame);
		}
		else if(poll_fd.revents & POLLNVAL || poll_fd.revents & POLLERR || poll_fd.revents & POLLHUP)
			break;
	}

	return NULL;
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

	int result = pthread_create(&threads[THREAD_MAIN], NULL, main_loop, NULL);
	if(result != 0) {
		perror("Failed to create main thread");
		exit(1);
	}
	result = pthread_create(&threads[THREAD_TCP_SLOW], NULL, tcp_timer_slow, NULL);
	if(result != 0) {
		perror("Failed to create TCP slow thread");
		exit(1);
	}
	result = pthread_create(&threads[THREAD_TCP_FAST], NULL, tcp_timer_fast, NULL);
	if(result != 0) {
		perror("Failed to create TCP fast thread");
		exit(1);
	}

	printf("Created threads\n\n");
}

void finish() {
	RUNNING = 0;

	free_tap_device();
	for(int i = 0; i < THREAD_COUNT; i++) {
		pthread_join(threads[i], NULL);
	}
}

int main() {
	setup();

	getchar();  // shut down on input
	printf("Shutting down...\n");

	finish();
}