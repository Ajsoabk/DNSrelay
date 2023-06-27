
#ifndef DNSPARSER
#define DNSPARSER

int parse_Dns_Message(char* msg,int len,packet_Information *pac);

int parse_Dns_query(char* msg,int len,packet_Information *pac);
#endif
