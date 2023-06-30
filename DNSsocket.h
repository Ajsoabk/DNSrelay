#ifndef DNSSOCKET_H
#define DNSSOCKET_H
#include"DNSpacket.h"
#include"Debugger.h"
int initilization(int argc, char **argv);
int my_recv_dns_msg();
int cleanup_All();

void log_level_switch_to(LOG_LEVEL new_level);
int change_dns_server_name(char *dns_ip);
#endif