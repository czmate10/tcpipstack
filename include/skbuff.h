#pragma once

#include <stdlib.h>

#include "list.h"
#include "tap.h"

struct sk_buff {
	uint8_t manual_free;  // eth_write() should not free() it
	struct net_dev* dev;
	uint32_t size;

	uint32_t payload_size;

	uint8_t *data;
};

struct sk_buff* skb_alloc(uint32_t size);
void skb_free(struct sk_buff *skb);