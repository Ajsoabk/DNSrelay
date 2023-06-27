#ifndef DNSSOCKET_H
#define DNSSOCKET_H
#include"DNSpacket.h"

int initilization();
int my_recv_dns_msg(packet_Information *pac);
int cleanup_All();

#endif