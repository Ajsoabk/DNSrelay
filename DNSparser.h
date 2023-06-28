
#ifndef DNSPARSER
#define DNSPARSER

int parse_Dns_Message(uint8_t* msg,int len,packet_Information *pac);

int parse_Dns_query(uint8_t* msg,int len,packet_Information *pac);
#endif
