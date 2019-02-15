#include "tcp.h"

LIST_HEAD(tcp_socket_list);


struct tcp_socket* tcp_socket_new(struct net_dev *device, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port) {
    struct tcp_socket* tcp_socket = (struct tcp_socket*)malloc(sizeof(struct tcp_socket));
    if(tcp_socket == NULL) {
        perror("could not allocate memory for TCP socket");
        exit(1);
    }
    memset(tcp_socket, 0, sizeof(struct tcp_socket));

    tcp_socket->state = TCPS_CLOSED;
    tcp_socket->mss = device->mtu - (uint16_t)IP_HEADER_SIZE - (uint16_t)TCP_HEADER_SIZE;
    tcp_socket->rto = 1000;  // RFC6298: 1 second or greater first
    tcp_socket->iss = (uint32_t)lrand48();
    tcp_socket->snd_nxt = tcp_socket->iss;
    tcp_socket->snd_una = tcp_socket->iss;
    tcp_socket->rcv_wnd = TCP_INITIAL_WINDOW;
    tcp_socket->snd_wnd = TCP_INITIAL_WINDOW;

    tcp_socket->sock.dev = device;
    tcp_socket->sock.protocol = IPPROTO_TCP;
    tcp_socket->sock.source_ip = device->ipv4;
    tcp_socket->sock.dest_ip = dest_ip;
    tcp_socket->sock.source_port = source_port;
    tcp_socket->sock.dest_port = dest_port;

    list_add(&tcp_socket->list, &tcp_socket_list);

    return tcp_socket;
}

struct tcp_socket* tcp_socket_get(uint32_t source_ip, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port) {
    struct list_head *list_item;
    struct tcp_socket *tcp_socket_item;

    list_for_each(list_item, &tcp_socket_list) {
        tcp_socket_item = list_entry(list_item, struct tcp_socket, list);

        if(tcp_socket_item == NULL)
            return NULL;

        if(tcp_socket_item->sock.source_ip == source_ip && tcp_socket_item->sock.dest_ip == dest_ip &&
           tcp_socket_item->sock.source_port == source_port && tcp_socket_item->sock.dest_port == dest_port) {
            return tcp_socket_item;
        }
    }

    return NULL;
}

void tcp_socket_free_queues(struct tcp_socket *tcp_socket) {
    struct tcp_buffer_queue_entry *entry = tcp_socket->out_queue_head;
    while(entry != NULL) {
        struct tcp_buffer_queue_entry *tmp = entry->next;
        skb_free(entry->sk_buff);
        free(entry);
        entry = tmp;
    }

    entry = tcp_socket->in_queue_head;
    while(entry != NULL) {
        struct tcp_buffer_queue_entry *tmp = entry->next;
        skb_free(entry->sk_buff);
        free(entry);
        entry = tmp;
    }
}

void tcp_socket_free(struct tcp_socket *tcp_socket) {
    if(tcp_socket == NULL)
        return;

    tcp_socket->state = TCPS_CLOSED;

    list_del(&tcp_socket->list);
    free(tcp_socket);
}