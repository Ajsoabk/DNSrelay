#ifndef DNSCACHE_H
#define DNSCACHE_H

//
// Created by 86187 on 2023/6/29.
//

#include<stdint.h>
#include "DNSpacket.h"

void printCache();
void add_rr(char *rName, uint16_t rType, uint32_t ttl, char *rData);

#endif //DNSCACHE_H
