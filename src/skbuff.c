#include <string.h>
#include <stdio.h>
#include "skbuff.h"


struct sk_buff* skb_alloc(uint32_t size) {
	struct sk_buff* buff = (struct sk_buff*)malloc(sizeof(struct sk_buff));
	if(buff == NULL) {
		perror("could not allocate memory for socket buffer");
		exit(1);
	}
	memset(buff, 0, sizeof(struct sk_buff));

	buff->size = size;
	buff->data = malloc(size);
	buff->manual_free = 0;

	memset(buff->data, 0, size);

	return buff;
}

void skb_free(struct sk_buff *skb) {
	free(skb->data);
	free(skb);
}