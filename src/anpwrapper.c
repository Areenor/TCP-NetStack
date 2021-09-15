/*
 * Copyright [2020] [Animesh Trivedi]
 *
 * This code is part of the Advanced Network Programming (ANP) course
 * at VU Amsterdam.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

//XXX: _GNU_SOURCE must be defined before including dlfcn to get RTLD_NEXT symbols
#define _GNU_SOURCE

#include <dlfcn.h>
#include "systems_headers.h"
#include "linklist.h"
#include "anpwrapper.h"
#include "tcp.h"
#include "init.h"
#include "subuff.h"
#include "ethernet.h"
#include "utilities.h"
#include "ip.h"
#include "arp.h"
#include "timer.h"
#include "config.h"
#include "anpsocket.h"
#include "LinkedList.h"

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static ssize_t (*_send)(int fd, const void *buf, size_t n, int flags) = NULL;
static ssize_t (*_recv)(int fd, void *buf, size_t n, int flags) = NULL;

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int sockfd) = NULL;

struct node* fdList = NULL;
int fd_counter = 50000;
int port_counter = 30000;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condEstablished = PTHREAD_COND_INITIALIZER;
pthread_cond_t condAllSent = PTHREAD_COND_INITIALIZER;
pthread_cond_t condClosed = PTHREAD_COND_INITIALIZER;
pthread_cond_t condWindow = PTHREAD_COND_INITIALIZER;
pthread_cond_t condReceived = PTHREAD_COND_INITIALIZER;

static int is_socket_supported(int domain, int type, int protocol)
{
    if (domain != AF_INET){
        return 0;
    }
    if (!(type & SOCK_STREAM)) {
        return 0;
    }
    if (protocol != 0 && protocol != IPPROTO_TCP) {
        return 0;
    }
    printf("supported socket domain %d type %d and protocol %d \n", domain, type, protocol);
    return 1;
}

// TODO: ANP milestone 3 -- implement the socket, and connect calls
int socket(int domain, int type, int protocol) {
    if (is_socket_supported(domain, type, protocol)) { //use new linked list
        //TODO: implement your logic here
        pthread_mutex_lock(&mutex);

        struct anpSocket* sockStruct = malloc(sizeof(struct anpSocket));
        sockStruct->fd = fd_counter;
        addNode(&fdList, sockStruct);
        sub_queue_init(&sockStruct->recvQueue);
        if (fdList == NULL) { 
            printf("HEAD IS NULL\n");
            return -1;
        }
        int returnVal = sockStruct->fd;


        fd_counter++;
        pthread_mutex_unlock(&mutex);
        return returnVal;
    }
    // if this is not what anpnetstack support, let it go, let it go!
    return _socket(domain, type, protocol);
}

int isSocket(int fd) {
    if (findNodeByFd(&fdList, fd) != NULL) {
        return 1;
    }
    return 0;
}

void *sendSynPacket(void *threadArg) {
    printf("sending SYN\n");
    struct sendArgStruct *argv = threadArg;
    int res = ip_output(ntohl(argv->addr_info->sin_addr.s_addr), argv->sub);
    if (res < 0) {
        printf("Failed to initiate connect, aborting");
        bool failed = true;
        argv->failedPacket = &failed;
        pthread_cond_signal(&condEstablished);
    }
}

void *resendFailed(void *threadArg) {
    printf("resend failed\n");
    struct sendArgStruct *argv = threadArg;
    argv->ourPort->socket->totalFinishedSends++;
    bool failed = true;
    argv->failedPacket = &failed;
    pthread_cond_signal(&condAllSent);

}

void *resendFailedPacket(void *threadArg) {
    printf("resending due to missing ack\n");
    struct sendArgStruct *argv = threadArg;
    ip_output(ntohl(argv->ourPort->socket->destIp), argv->sub);
    timer_add(500, resendFailed, threadArg);
}

struct subuff* generateAckSub(int seq, int ack, uint16_t srcPort, uint16_t dstPort) {
    struct subuff *ackSub = allocateTcpSub(0);
    struct tcphdr *tcp;
    tcp = (struct tcphdr *) sub_push(ackSub, sizeof(struct tcphdr));
    initializeTcpSub(tcp, seq, ack, srcPort, dstPort);
    tcp->flag_ack = 1;
    return ackSub;
}


int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    pthread_mutex_lock(&mutex); //same lock as in socket, to ensure extra fd's and connection does not get made at the same time
    if(isSocket(sockfd)){
        struct subuff *arpSub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN);
        sub_reserve(arpSub, ETH_HDR_LEN + IP_HDR_LEN);

        struct subuff *tcpSub = allocateTcpSub(0); //0 no payload
        struct tcphdr *tcp;
        tcp = (struct tcphdr *) sub_push(tcpSub, sizeof(struct tcphdr));

        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr; //cast to sockaddr_in to retrieve ip and port seen family is AF_INET

        initializeTcpSub(tcp, htonl(1), htonl(0), htons(port_counter), addr_in->sin_port);

        findNodeByFd(&fdList, sockfd)->socket->port = port_counter;
        port_counter++;

        tcp->flag_syn = 1;
        tcp->csum = do_tcp_csum((uint8_t *) tcp, 20, IPP_TCP, ip_str_to_n32("10.0.0.4"),ip_str_to_n32(inet_ntoa(addr_in->sin_addr)) ); //20 size tcp header no payload

        struct node *currPort = findNodeByFd(&fdList, sockfd);
        currPort->socket->destIp = addr_in->sin_addr.s_addr;
        currPort->socket->state = SYN_SENT;

        bool failCheck = false;
        struct sendArgStruct *threadArg = malloc(sizeof(struct sendArgStruct));
        threadArg->sub = tcpSub;
        threadArg->addr_info = addr_in;
        threadArg->failedPacket = &failCheck;

        if(!arp_get_hwaddr(ntohl(addr_in->sin_addr.s_addr))) {
            ip_output(ntohl(addr_in->sin_addr.s_addr), arpSub);
            timer_add(500, sendSynPacket, threadArg);
        }
        else {
            sendSynPacket(threadArg);
        }

        struct timespec timeStruct;
        timeStruct.tv_sec = time(NULL) + 2;
        timeStruct.tv_nsec = 0;

        while(currPort->socket->state != ESTABLISHED && !failCheck) {
            int t = pthread_cond_timedwait(&condEstablished, &mutex, &timeStruct);
            if(t == ETIMEDOUT) {
                errno = ECONNREFUSED;
                pthread_mutex_unlock(&mutex);
                return -1;
            }
            else if(failCheck) {
                errno = ENETUNREACH;
                pthread_mutex_unlock(&mutex);
                return -1;
            }
        }

        pthread_mutex_unlock(&mutex);
        return 0;
    }
    // the default path
    pthread_mutex_unlock(&mutex);
    return _connect(sockfd, addr, addrlen);
}

void receive_connect(struct subuff *sub) {
    struct tcphdr *incTcp;
    struct iphdr *ih = IP_HDR_FROM_SUB(sub);
    ih->saddr = ntohl(ih->saddr);
    ih->daddr = ntohl(ih->daddr);
    ih->len = ntohs(ih->len);
    ih->id = ntohs(ih->id);

    incTcp = (struct tcphdr *) ih->data;
    if(incTcp->flag_syn && incTcp->flag_ack) {

        uint32_t newAck = ntohl(incTcp->seq_num);
        newAck = newAck + 1;

        struct subuff *newOutgoingSub = allocateTcpSub(0);
        struct tcphdr *newOutgoingTcp;
        newOutgoingTcp = (struct tcphdr *) sub_push(newOutgoingSub, sizeof(struct tcphdr));
        initializeTcpSub(newOutgoingTcp, incTcp->ack_num, htonl(newAck), incTcp->dest_port, incTcp->source_port);
        newOutgoingTcp->flag_ack = 1;
        newOutgoingTcp->csum = do_tcp_csum((uint8_t *) newOutgoingTcp, 20, IPP_TCP, ip_str_to_n32("10.0.0.4"), ih->saddr); //20 is size tcp header with no payload

        struct node *ourPort = findNodeByPort(&fdList, ntohs(incTcp->dest_port));

        ourPort->socket->lastSeqn = newOutgoingTcp->seq_num;
        ourPort->socket->lastAckn = newOutgoingTcp->ack_num;
        ourPort->socket->destPort = newOutgoingTcp->dest_port;
        ourPort->socket->lastWindowSize = ntohs(incTcp->window_size);

        ourPort->socket->state = ESTABLISHED;

        ip_output(htonl(ih->saddr), newOutgoingSub);

        pthread_cond_signal(&condEstablished);
    }
}

void fin_recieve(struct subuff *sub){
    struct iphdr *ih = IP_HDR_FROM_SUB(sub);
    struct tcphdr *incTcp = (struct tcphdr *) ih->data;
    uint32_t seq = incTcp->ack_num;
    uint32_t ack = ntohl(incTcp->seq_num) + 1;
    ack = htonl(ack);
    struct node *ourPort = findNodeByPort(&fdList, ntohs(incTcp->dest_port));
    struct subuff *ackSub = generateAckSub(seq, ack, incTcp->dest_port, incTcp->source_port);

    struct iphdr *ih2 = IP_HDR_FROM_SUB(ackSub);
    struct tcphdr *tcp = (struct tcphdr *) ih2->data;
    tcp->csum = do_tcp_csum((uint8_t *) tcp, 20, IPP_TCP, ip_str_to_n32("10.0.0.4"),  ourPort->socket->destIp);
    ip_output(ih->saddr, ackSub);
    ourPort->socket->state = CLOSED;
    pthread_cond_signal(&condClosed);
}

ssize_t receive_data(struct anpSocket* sock, size_t len, void* buff, int* received) {
    while(*received < (int)len) {
        struct subuff  *sub = sub_peek(&sock->recvQueue);
        if (sub) {
            struct tcphdr *incTcp;
            struct iphdr *ih = IP_HDR_FROM_SUB(sub);
            incTcp = (struct tcphdr *) ih->data;
            void *incData = (void *) incTcp->data;
            uint32_t incDataSize = IP_PAYLOAD_LEN(ih) - incTcp->data_offset * 4;
            memcpy(buff + *received, incData, incDataSize);

            uint32_t seq = incTcp->ack_num;
            uint32_t ack = ntohl(incTcp->seq_num) + incDataSize;
            ack = htonl(ack);

            struct node *ourPort = findNodeByPort(&fdList, ntohs(incTcp->dest_port));
            struct subuff *ackSub = generateAckSub(seq, ack, incTcp->dest_port, incTcp->source_port);

            struct iphdr *ih2 = IP_HDR_FROM_SUB(ackSub);
            struct tcphdr *tcp = (struct tcphdr *) ih2->data;
            tcp->csum = do_tcp_csum((uint8_t *) tcp, 20, IPP_TCP, ip_str_to_n32("10.0.0.4"), ourPort->socket->destIp);

            ip_output(ih->saddr, ackSub);

            ourPort->socket->lastSeqn = seq;
            ourPort->socket->lastAckn = ack;
            ourPort->socket->lastWindowSize = ntohs(incTcp->window_size);
            sub_dequeue(&sock->recvQueue);
            free_sub(sub);

            *received += incDataSize;
        }
    }
    pthread_cond_signal(&condReceived);
    return len;
}


void receiveTcpSub(struct subuff *sub) {
    struct tcphdr *incTcp;
    struct iphdr *ih = IP_HDR_FROM_SUB(sub);
    size_t incDataSize;

    incTcp = (struct tcphdr *) ih->data;
    struct node *currNode = findNodeByPort(&fdList, ntohs(incTcp->dest_port));
    incDataSize = IP_PAYLOAD_LEN(ih) - incTcp->data_offset * 4;

    if(incDataSize > 0 && currNode->socket->state == ESTABLISHED) {
        sub_queue_tail(&currNode->socket->recvQueue, sub);
    }
    else if(currNode->socket->state == SYN_SENT) {
        receive_connect(sub);
    }
    else if(currNode->socket->state == FIN_WAIT_1){
        fin_recieve(sub);
    }
    else if(incTcp->flag_ack) {
        struct node *ourPort = findNodeByPort(&fdList, ntohs(incTcp->dest_port));
        struct sendArgStruct *timerArg;

        for (int i = 0; i < ourPort->socket->totalTimers; i++) {  //compares the ack number of the tcp packet with the outgoing packets waiting for approval
            timerArg = ourPort->socket->timerPointers[i]->arg;
            if (ntohl(timerArg->sentSeq) == ntohl(incTcp->ack_num)) { //if found, update window and cross it off the waiting list
                timer_cancel(ourPort->socket->timerPointers[i]);
                ourPort->socket->totalFinishedSends++;
                ourPort->socket->lastWindowSize = ntohs(incTcp->window_size);
                timerArg->sentSeq = 0;
                pthread_cond_signal(&condWindow);
                pthread_cond_signal(&condAllSent);
                break;
            }
        }
    }
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    pthread_mutex_lock(&mutex); //same lock as in socket, to ensure extra fd's and connection does not get made at the same time
    if(isSocket(sockfd)) {
        struct node *ourPort = findNodeByFd(&fdList, sockfd); //finds socket using sockfd

        if(ourPort->socket->state != ESTABLISHED) {
            errno = ENOTCONN;
            pthread_mutex_unlock(&mutex);
            return -1;
        }

        ourPort->socket->totalTimers = 0;
        ourPort->socket->totalFinishedSends = 0;
        int totalSend = 0;
        uint32_t bytesLeftToSend = len;
        uint32_t payloadSize = 0;

        uint32_t bytesSent = 0;
        bool packetFailure = false;
        bool *sendFailed = &packetFailure;
        bool finalPackage = false;
        for(int j=0; j < 500; j++) {
            ourPort->socket->timerPointers[j] = 0;
        }
        uint32_t windowSize;

        while(bytesLeftToSend > 0){

            while(ourPort->socket->lastWindowSize <= 0) { //when window 0, wait till more space is available
                pthread_cond_wait(&condWindow, &mutex);
            }

            windowSize = ourPort->socket->lastWindowSize;
            if((windowSize >= 1460) && (bytesLeftToSend >= 1460)){
                payloadSize = 1460;
            }
            else if((bytesLeftToSend < windowSize) && (bytesLeftToSend < 1460)) {
                payloadSize = bytesLeftToSend;
                finalPackage = true;
            }
            else {
                payloadSize = windowSize;
            }

            ourPort->socket->lastWindowSize = windowSize - payloadSize;
            struct subuff *tcpSub = allocateTcpSub(payloadSize);

            void *payload = sub_push(tcpSub, payloadSize);
            memcpy(payload, buf + bytesSent, payloadSize);

            struct tcphdr *tcp = (struct tcphdr *) sub_push(tcpSub, sizeof(struct tcphdr));
            initializeTcpSub(tcp, ourPort->socket->lastSeqn + htonl(bytesSent), ourPort->socket->lastAckn, htons(ourPort->socket->port), ourPort->socket->destPort);

            tcp->flag_ack = 1;
            if(finalPackage) {
                tcp->flag_psh = 1;
            }

            tcp->csum = do_tcp_csum((uint8_t *) tcp, 20 +  payloadSize, IPP_TCP, ip_str_to_n32("10.0.0.4"),  ourPort->socket->destIp); //20 size tcp header no payload

            struct sendArgStruct *threadArg = malloc(sizeof(struct sendArgStruct));
            threadArg->sub = tcpSub;
            threadArg->sentSeq = ntohl(ourPort->socket->lastSeqn) + bytesSent + payloadSize;
            threadArg->sentSeq = htonl(threadArg->sentSeq);
            threadArg->ourPort = ourPort;
            threadArg->failedPacket = sendFailed;

            struct timer *ackTimer = timer_add(500, resendFailedPacket, threadArg); //500 ms as found in the RFC

            ourPort->socket->timerPointers[ourPort->socket->totalTimers] = ackTimer;
            ourPort->socket->totalTimers++;
            ip_output(ntohl(ourPort->socket->destIp), tcpSub);

            bytesLeftToSend = bytesLeftToSend - payloadSize;
            bytesSent = bytesSent + payloadSize;
            totalSend++;
        }

        while( totalSend > ourPort->socket->totalFinishedSends) {
            pthread_cond_wait(&condAllSent, &mutex);
        }
        if(*sendFailed) {
            errno = ECONNRESET;
            pthread_mutex_unlock(&mutex);
            return -1;
        }
        pthread_mutex_unlock(&mutex);
        return len;
    }
    // the default path
    pthread_mutex_unlock(&mutex);
    return _send(sockfd, buf, len, flags);
}

ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    pthread_mutex_lock(&mutex);
    struct node *sockNode = findNodeByFd(&fdList, sockfd);
    if(isSocket(sockfd)) {
        if(sockNode->socket->state != ESTABLISHED) {
            errno = ENOTCONN;
            pthread_mutex_unlock(&mutex);
            return -1;
        }
        int received = 0;
        receive_data(sockNode->socket, len, buf, &received);
        while(received != len) {
            pthread_cond_wait(&condReceived, &mutex);
        }
        pthread_mutex_unlock(&mutex);
        return len;
    }
    // the default path
    pthread_mutex_unlock(&mutex);
    return _recv(sockfd, buf, len, flags);
}


int close (int sockfd){
    pthread_mutex_lock(&mutex);

    if(isSocket(sockfd)) {
        struct node *sockNode = findNodeByFd(&fdList, sockfd);

        struct subuff *tcpSub = allocateTcpSub(0); //0 no payload
        struct tcphdr *tcp;
        tcp = (struct tcphdr *) sub_push(tcpSub, sizeof(struct tcphdr));
        initializeTcpSub(tcp, sockNode->socket->lastSeqn, sockNode->socket->lastAckn, htons(sockNode->socket->port), sockNode->socket->destPort);
        tcp->flag_fin = 1;
        tcp->flag_ack = 1;
        tcp->csum = do_tcp_csum((uint8_t *) tcp, 20, IPP_TCP, ip_str_to_n32("10.0.0.4"),  sockNode->socket->destIp);
        ip_output(ntohl(sockNode->socket->destIp), tcpSub);
        sockNode->socket->state = FIN_WAIT_1;
        while(sockNode->socket->state != CLOSED) {
            pthread_cond_wait(&condClosed, &mutex);
        }
        pthread_mutex_unlock(&mutex);
        return 0;
    }

    // the default path
    pthread_mutex_unlock(&mutex);
    return _close(sockfd);
}

void _function_override_init()
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");
    _socket = dlsym(RTLD_NEXT, "socket");
    _connect = dlsym(RTLD_NEXT, "connect");
    _send = dlsym(RTLD_NEXT, "send");
    _recv = dlsym(RTLD_NEXT, "recv");
    _close = dlsym(RTLD_NEXT, "close");
}
