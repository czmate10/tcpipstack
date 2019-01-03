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

#include "tap.h"
#include "eth.h"
#include "arp.h"
#include "ipv4.h"
#include "tcp.h"


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


int main() {
	// Variables
	char dev_name[IFNAMSIZ];
	strcpy(dev_name, "tap0");

	// Setup internal stuff
	struct netdev* dev = init_tap_device(dev_name);

	printf("Using TAP device %s\n\n", dev_name);

	// Read packets
	while(1) {
		struct eth_frame *eth_frame = malloc(ETHERNET_MAX_SIZE);
		if(eth_frame == NULL) {
			perror("could not allocate memory for ethernet packet");
			exit(1);
		}

		uint16_t num_bytes = eth_read(dev, eth_frame);
		handle_eth_packet(dev, eth_frame);

		free(eth_frame);
	}

	free_tap_device();
}