#ifndef DNSPACKET
#define DNSPACKET

#define DNSHEADER_MINSIZE 12
#define MAX_HOST_NAME 64
#define A 		0x0100
#define AAAA 	0x1c00
#include<stdint.h>
typedef struct DNSHeader {
    uint16_t ID;
    uint16_t flags;//QR,Opcode(4 bytes),AA,TC,RD,RA,Z(3 bytes),RCODE
	/*
	标*的是需要检查的
	标**的是可能需要更改的
**	QR	 	1b 	query(0),response(1)
*	OPCODE	4b	standard query(0),inverse query(1),server status request(2),
	AA		1b	authority response(1),
	TC		1b	truncation(1),
	RD		1b	Recursion Desired(1),
	RA		1b	Recursion Available(1)
	Z
**	RCode	1b	no error(0)
				format error(1)
**				server failure(2)
**				name error(3)
				Not Implemented(4)
				Refused(5)
	*/
    uint16_t QDcnt;//number of question(s)
    uint16_t ANcnt;//number of answer(s) 
    uint16_t NScnt;//number of server(s)
    uint16_t ARcnt;//number of resource record(s)
}DNSHeader;
#define GET_ID(DNSHEADER_PTR)		(ntohs(DNSHEADER_PTR->ID))
#define GET_QR(DNSHEADER_PTR)		((ntohs(DNSHEADER_PTR->flags)>>15)&1)
#define GET_TC(DNSHEADER_PTR)		((ntohs(DNSHEADER_PTR->flags)>>9)&1)
#define GET_RD(DNSHEADER_PTR)		((ntohs(DNSHEADER_PTR->flags)>>8)&1)
#define GET_RA(DNSHEADER_PTR)		((ntohs(DNSHEADER_PTR->flags)>>7)&1)
#define GET_RCODE(DNSHEADER_PTR)			((ntohs(DNSHEADER_PTR->flags))&((1<<3)-1))
#define GET_OPCODE(DNSHEADER_PTR)			((ntohs(DNSHEADER_PTR->flags)>>11)&((1<<4)-1))
#define GET_QDcnt(DNSHEADER_PTR)			(ntohs(DNSHEADER_PTR->QDcnt))
#define GET_ANcnt(DNSHEADER_PTR)			(ntohs(DNSHEADER_PTR->ANcnt))
#define GET_NScnt(DNSHEADER_PTR)			(ntohs(DNSHEADER_PTR->NScnt))
#define GET_ARcnt(DNSHEADER_PTR)			(ntohs(DNSHEADER_PTR->ARcnt))

#define NO_ERROR_REPLY_CODE						0
#define FORMAT_ERROR_REPLY_CODE					1
#define SERVER_FAILURE_REPLY_CODE				2
#define SET_RESPONSE(DNSHEADER_PTR)			((DNSHEADER_PTR->flags)&=(1<<15))
#define SET_REPLY_CODE(DNSHEADER_PTR,value)	((DNSHEADER_PTR->flags)=htons(((~(((1<<16)-1)))&ntohs(DNSHEADER_PTR))|(value))


typedef struct DNSQuestion {
    char *host_name;
    uint16_t host_type;
    uint16_t net_class;
    struct DNSQuestion *next;
}DNSQuestion;

typedef struct DNSResourceRecord{
	//待请求的资源名
	char *name;
	
	/*
	type 	A(1),AAAA(28),CNAME(5)
	*/
	uint16_t type;
	
	/*
	class	IN(1)
	*/
	uint16_t net_class;
	
	//time to live
	uint32_t ttl;
	
	//回答
	uint8_t *rdata;
	struct DNSResourceRecord* next;
}DNSResourceRecord;


typedef struct packet_Information{
	char source_ip[50];
	int source_port;
	int packet_id;
	int rcode;
	
	//link list
	DNSQuestion* question_head;
	DNSResourceRecord* rr_head;
	
	int packet_type;
	int query_type;
	int recursion_desired;
	int qdcnt;
	int ancnt;
	
}packet_Information;
void clean_up_packet(packet_Information *pac);
#endif