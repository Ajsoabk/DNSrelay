#ifndef DNSCACHE_H
#define DNSCACHE_H

#include "DNSpacket.h"

int cache_response(packet_Information *pac);
void printCache();
void add_rr(DNSResourceRecord *rrptr);


#endif