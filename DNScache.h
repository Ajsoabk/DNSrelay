#ifndef DNSCACHE_H
#define DNSCACHE_H
#include "DNSpacket.h"
#define DNSRR DNSResourceRecord

int cache_response(packet_Information *pac);

DNSResourceRecord* find_in_cache(DNSQuestion* q_ptr);
void flush_expired_cache();
void print_cache_debug();
#endif