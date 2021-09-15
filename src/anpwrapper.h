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

#ifndef ANPNETSTACK_ANPWRAPPER_H
#define ANPNETSTACK_ANPWRAPPER_H
#include "subuff.h"
#include "anpsocket.h"
void receive_connect(struct subuff *sub);
void receiveTcpSub(struct subuff *sub);
int isSocket(int fd);
void *sendSynPacket(void *threadArg);
void *resendFailed(void *threadArg);
void *resendFailedPacket(void *threadArg);
struct subuff* generateAckSub(int seq, int ack, uint16_t srcPort, uint16_t dstPort);
void fin_recieve(struct subuff *sub);
ssize_t receive_data(struct anpSocket* sock, size_t len, void* buff, int* received);

void _function_override_init();

#endif //ANPNETSTACK_ANPWRAPPER_H
