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
#include <sys/poll.h>

#include "tap.h"
#include "eth.h"
#include "arp.h"
#include "ipv4.h"
#include "tcp.h"


int RUNNING = 1;
struct netdev* device = NULL;


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

void *main_loop(void *params) {
	// Read packets
	while(RUNNING) {
		struct eth_frame *eth_frame = malloc(ETHERNET_MAX_SIZE);
		if(eth_frame == NULL) {
			perror("could not allocate memory for ethernet packet");
			exit(1);
		}

		uint16_t num_bytes = eth_read(device, eth_frame);
		handle_eth_packet(device, eth_frame);

		free(eth_frame);
	}
	return NULL;
}

void setup() {
	// TAP device
	char dev_name[IFNAMSIZ];
	strcpy(dev_name, "tap0");
	device = init_tap_device(dev_name);
	printf("Using TAP device %s\n\n", dev_name);
}

void finish() {
	free_tap_device();
}

int main() {
	setup();

	pthread_t main_thread;
	int result = pthread_create(&main_thread, NULL, main_loop, NULL);
	if(result != 0) {
		perror("Failed to create thread");
		exit(1);
	}

	getchar();
	printf("Shutting down...\n");

	RUNNING = 0;
	pthread_join(main_thread, NULL);
	finish();
}