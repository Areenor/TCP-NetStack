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

#include "icmp.h"
#include "ip.h"
#include "utilities.h"


void icmp_rx(struct subuff *sub)
{
    //FIXME: implement your ICMP packet processing implementation here
    //figure out various type of ICMP packets, and implement the ECHO response type (icmp_reply)
    struct icmp *icmpHead;
    struct iphdr *ih = IP_HDR_FROM_SUB(sub);
    ih->saddr = ntohl(ih->saddr);
    ih->daddr = ntohl(ih->daddr);
    ih->len = ntohs(ih->len);
    ih->id = ntohs(ih->id);

    //uint16_t csum = -1;


    icmpHead = (struct icmp *) ih->data;
    printf("DATA BOI: %d, %d \n", icmpHead->type, icmpHead->code);

    //csum = do_csum(icmpHead, 8, 0);
    /*
    if (csum != 0) {
        printf("Error: invalid checksum, dropping packet");
        free_sub(sub);
        return;
    }*/

    if(icmpHead->type == ICMP_V4_ECHO) {
        icmp_reply(sub);
    }
    free_sub(sub);
}

void icmp_reply(struct subuff *sub)
{
    struct icmp *icmpHead;
    struct iphdr *ih = IP_HDR_FROM_SUB(sub);
    ih->saddr = ntohl(ih->saddr);
    ih->daddr = ntohl(ih->daddr);
    ih->len = ntohs(ih->len);
    ih->id = ntohs(ih->id);



    sub_reserve(sub, ETH_HDR_LEN + ih->len );
    sub_push(sub, ih->len - IP_HDR_LEN );

    icmpHead = (struct icmp *) ih->data;


    icmpHead->checksum = 0;
    icmpHead->checksum = htons(icmpHead->checksum);
    icmpHead->type = ICMP_V4_REPLY;
    icmpHead->code = 0;


    icmpHead->checksum = do_csum(icmpHead, 8, 0);
    sub->protocol = 1;
    printf("DATA BOI: %d %d \n", icmpHead->type, icmpHead->code);
    printf("IP INT: %d\n", ih->saddr);
    ip_output(ih->saddr, sub);
    //FIXME: implement your ICMP reply implementation here
    // preapre an ICMP response buffer
    // send it out on ip_ouput(...)
}
