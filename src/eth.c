#include <netinet/in.h>
#include <string.h>
#include <malloc.h>
#include <linux/if_ether.h>
#include "../include/eth.h"


uint16_t eth_read(struct net_dev *dev, struct eth_frame *frame) {
	ssize_t bytes = read((int)dev->sock_fd, frame, ETHERNET_MAX_SIZE);
	if (bytes == -1) {
		perror("failed to read data");
		return 0;
	}

	frame->eth_type = ntohs(frame->eth_type);

	return (uint16_t)bytes;
}

int eth_write_raw(struct net_dev *dev, uint8_t dest_mac[], uint16_t eth_type, struct eth_frame *frame, uint16_t payload_len) {
	memcpy(frame->mac_dest, dest_mac, sizeof(frame->mac_dest));
	memcpy(frame->mac_source, dev->hwaddr, sizeof(frame->mac_source));
	frame->eth_type = htons(eth_type);

	ssize_t bytes = write(dev->sock_fd, frame, (size_t)(ETHERNET_HEADER_SIZE + payload_len));

	if(bytes == -1) {
		perror("failed to write data");
		return 0;
	}

	return (int)bytes;
}


int eth_write(struct net_dev *dev, uint8_t dest_mac[], uint16_t eth_type, struct sk_buff *buffer) {
	struct eth_frame *frame = eth_frame_from_skb(buffer);
	memcpy(frame->mac_dest, dest_mac, sizeof(frame->mac_dest));
	memcpy(frame->mac_source, dev->hwaddr, sizeof(frame->mac_source));
	frame->eth_type = htons(eth_type);

	ssize_t bytes = write(dev->sock_fd, buffer->data, (size_t)(buffer->size));

	if(bytes == -1) {
		perror("failed to write data");
		return 0;
	}

	return (int)bytes;
}


