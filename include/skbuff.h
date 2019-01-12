#pragma once

#include <stdlib.h>

#include "list.h"
#include "tap.h"

struct sk_buff {
	struct list_head list;

	struct net_dev* dev;
	uint32_t size;

	uint32_t payload_size;
	uint32_t seq;
	uint32_t seq_end;

	uint8_t *data;
};

struct sk_buff* skb_alloc(uint32_t size);
void skb_free(struct sk_buff *skb);