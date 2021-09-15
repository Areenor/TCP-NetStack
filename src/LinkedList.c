#include "LinkedList.h"

void addNode(struct node** head, struct anpSocket* sock){
    printf("WERE IN ADD NODE\n");
    struct node *newFD = (struct node*) malloc(sizeof(struct node));
    if (*head == NULL) {
        *head = newFD;
    }
    newFD->socket = sock;
    newFD->socket->state = CLOSED;
    newFD->next = *head;
    *head = newFD;
}

struct node* findNodeByFd(struct node** head, uint32_t search_fd){
    if(head == NULL){
        printf("Can't find node: list is empty.\n");
        return NULL;
    }
    struct node* current = *head;
    while (current != NULL){
        if(current->socket->fd == search_fd){
            return current;
        }
        current = current->next;
    }
    printf("Node is not found.\n");
    return NULL;
}

struct node* findNodeByPort(struct node** head, uint32_t port){
    if(head == NULL){
        printf("Can't find node: list is empty.\n");
        return NULL;
    }
    struct node* current = *head;
    while (current != NULL){
        if(current->socket->port == port){
            return current;
        }
        current = current->next;
    }
    printf("Node is not found.\n");
    return NULL;
}



