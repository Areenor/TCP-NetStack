#ifndef ANPNETSTACK_ANPSOCKET_H
#define ANPNETSTACK_ANPSOCKET_H

#include "systems_headers.h"
#include "subuff.h"

#define CLOSED 0
#define ESTABLISHED 1
#define SYN_SENT 2
#define FIN_WAIT_1 3
#define FIN_WAIT_2 4
#define CLOSING 5
#define TIME_WAIT 6

struct anpSocket { //Fd, socket, IsEstablished
    struct subuff_head recvQueue;
    uint32_t fd;
    uint16_t port;
    int state;
    uint16_t lastWindowSize;
    uint32_t lastSeqn;
    uint32_t lastAckn;
    uint16_t destPort;
    uint32_t destIp;
    uint32_t totalTimers;
    uint32_t totalFinishedSends;
    struct timer *timerPointers[500];
};


#endif //ANPNETSTACK_ANPSOCKET_H