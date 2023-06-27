#include<stdlib.h>
#include<stdio.h>

#include<WinSock2.h>
#include "DNSpacket.h"
extern int debug_level;

int parse_Dns_query(char* msg,int len,packet_Information *pac){
	int label_len=0;
	int count_bytes=0;
	uint8_t* byte_ptr=NULL;
	int q_cnt=0;
	DNSHeader *header_ptr=(DNSHeader*)msg;
	DNSQuestion* question_tail=NULL;
	
	pac->question_head=NULL;
	pac->packet_id=GET_ID(header_ptr);
	pac->packet_type=0;
	pac->query_type=GET_OPCODE(header_ptr);
	pac->recursion_desired=1;
	q_cnt=GET_QDcnt(header_ptr);
	byte_ptr=msg+sizeof(DNSHeader);
	count_bytes+=sizeof(DNSHeader);
	//读取所有question 段
	while(q_cnt){
		q_cnt--;
		char *host_name=(char *)malloc(sizeof(char)*MAX_HOST_NAME);
		
		int pos=0;
		while((*byte_ptr)!='\0'){//读取其中一个question段中的每一级主机名
			label_len=*byte_ptr;
			byte_ptr++;
			count_bytes++;
			if(count_bytes>=len)
				return 1;
			//读取该级主机名中的每个字符
			while(label_len){
				label_len--;
				host_name[pos]=*byte_ptr;
				byte_ptr++;
				count_bytes++;
				if(count_bytes>=len)
					return 1;
				pos++;
			}
			host_name[pos]='.';
			
			pos++;
		}
		pos--;
		host_name[pos]='\0';
			
		DNSQuestion* question=(DNSQuestion*)malloc(sizeof(DNSQuestion));
		if(pac->question_head==NULL){
			pac->question_head=question;
			question_tail=question;
		}
		question_tail->next=question;
		question->next=NULL;
		question_tail=question;
		
		question->host_name=host_name;
		question->host_type=ntohs(*byte_ptr);
		byte_ptr++;
		question->net_class=ntohs(*byte_ptr);
		byte_ptr++;
		
	}
	return 0;
}
int parse_Dns_Message(char* msg,int len,packet_Information *pac){
	if(len<DNSHEADER_MINSIZE)
		return 1;
	
	DNSHeader *header_ptr=(DNSHeader*)msg;
	if(GET_QR(header_ptr)){
		
		pac->packet_id=GET_ID(header_ptr);
		pac->packet_type=1;
		return 0;
	}
	return parse_Dns_query(msg,len,pac);
}