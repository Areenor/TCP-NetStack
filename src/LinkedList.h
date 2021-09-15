#ifndef ANPNETSTACK_LINKEDLIST_H
#define ANPNETSTACK_LINKEDLIST_H
#include "anpsocket.h"
#include "systems_headers.h"

struct node {
    struct anpSocket* socket;
    struct node *next;
};

void addNode(struct node** head, struct anpSocket* sock);
struct node* findNodeByFd(struct node** head, uint32_t search_fd);
struct node* findNodeByPort(struct node** head, uint32_t port);

#endif //ANPNETSTACK_LINKEDLIST_H
