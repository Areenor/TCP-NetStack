
#ifndef ANPNETSTACK_TCP_H
#define ANPNETSTACK_TCP_H

#include "systems_headers.h"
#include "subuff.h"
#include "ip.h"

#define TCP_HDR_LEN sizeof(struct tcphdr)

struct tcphdr { //little endianness
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t reserved: 4;
    uint8_t data_offset : 4;
    uint8_t flag_fin : 1;
    uint8_t flag_syn : 1;
    uint8_t flag_rst : 1;
    uint8_t flag_psh : 1;
    uint8_t flag_ack : 1;
    uint8_t flag_urg : 1;
    uint8_t reservedTwo: 2;
    uint16_t window_size;
    uint16_t csum;
    uint16_t urgent;
    uint8_t data[];
} __attribute__((packed));

struct sendArgStruct {
    struct subuff *sub;
    struct node *ourPort;
    uint32_t sentSeq;
    bool *failedPacket;
    struct sockaddr_in *addr_info;
};

struct subuff* allocateTcpSub(int size) {
    int buffSize = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + size;
    struct subuff *sub = alloc_sub(buffSize);
    sub_reserve(sub, buffSize);
    sub->protocol = IPPROTO_TCP;
    return sub;
}


void initializeTcpSub(struct tcphdr *tcp, uint32_t seqn, uint32_t ackN, uint16_t sourcePort, uint16_t destPort) {
    tcp->source_port = sourcePort;
    tcp->dest_port = destPort;
    tcp->seq_num = seqn;
    tcp->ack_num = ackN;
    tcp->data_offset = 5; //5 32 bit words, min size
    tcp->reserved = 0;

    tcp->flag_ack = 0;
    tcp->flag_fin = 0;
    tcp->flag_psh = 0;
    tcp->flag_rst = 0;
    tcp->flag_syn = 0;
    tcp->flag_urg = 0;

    tcp->reservedTwo = 0;
    tcp->window_size = htons(32767);
    tcp->urgent = htons(0);
    tcp->csum = htons(0);

}
#endif //ANPNETSTACK_TCP_H
