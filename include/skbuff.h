#pragma once

#include <stdlib.h>
#include "tap.h"

struct sk_buff {
	struct sk_buff *next;
	struct sk_buff *prev;

	struct net_dev* dev;

	uint32_t size;
	uint8_t *data;
};

struct sk_buff* skb_alloc(uint32_t size);
void skb_free(struct sk_buff *skb);