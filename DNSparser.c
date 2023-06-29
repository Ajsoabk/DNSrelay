#include<stdlib.h>
#include<stdio.h>
#include<WinSock2.h>
#include<ws2tcpip.h>
#include "DNSpacket.h"
#include "Debugger.h"
#include "DNScache.h"
#define BigLittleSwap16(A)  ((((uint16_t)(A) & 0xff00) >> 8) |(((uint16_t)(A) & 0x00ff) << 8))

int is_compressed_name(uint8_t ch){
	return (ch&0xC0)==0xC0;
}
int parse_host_name(uint8_t *msg,unsigned short *cur,char *host_name,int *offset){
	log_debug(log_level_global,"cur=%ud,host_name=%s,name_offset=%d\n",*cur,host_name,*offset);
	int msg_offset=*cur;
	int name_offset=*offset;
	uint8_t label_len;
	while(msg[msg_offset]!='\0'){//读取每一级子域名
		label_len=*((uint8_t*)(msg+msg_offset));
		if(is_compressed_name(label_len)){//判断这个字节是否是偏移量
			//读取其后的两个字节并且转换成主机字节（小端方式）
			unsigned short tmp_offset=(BigLittleSwap16(*((uint16_t *)(msg+msg_offset))))&0x3fff;
			log_debug(log_level_global,"jump to %d\n",tmp_offset);
			msg_offset+=2;
			parse_host_name(msg,&tmp_offset,host_name,&name_offset);
			name_offset++;
			continue;
		}
		msg_offset++;
		//读取该级主机名中的每个字符
		while(label_len--){
			host_name[name_offset]=msg[msg_offset];
			msg_offset++;
			name_offset++;
		}
		host_name[name_offset]='.';
		name_offset++;
		if(msg[msg_offset]=='\0'){
			msg_offset++;
			break;
		}
	}
	name_offset--;
	host_name[name_offset]='\0';
	
	*offset=name_offset;
	*cur=msg_offset;
	log_debug(log_level_global,"complete parse host name at %d, the host name is %s and end at %d\n",*cur,host_name,*offset);
	return 0;
}		

int parse_resource_record(uint8_t *msg,unsigned short *ret_offset,DNSResourceRecord **rr){
	//解析name字段，即待请求的资源名
	log_debug(log_level_global,"parsing rr at %d\n",*ret_offset);
	unsigned short msg_offset=*ret_offset;
	char host_name[MAX_HOST_NAME];
	//ZeroMemory(..);
	SecureZeroMemory(host_name,MAX_HOST_NAME);
	int name_len=0;
	int data_len;
	parse_host_name(msg,&msg_offset,host_name,&name_len);
	log_debug(log_level_global,"host name parsed as %s with len %d\n",host_name,name_len);
	
	//tmp->name=host_name;why not?
	DNSResourceRecord *tmp=(DNSResourceRecord *)malloc(sizeof(DNSResourceRecord));
	if(tmp==NULL){
		log_err(log_level_global,"failed to alloc memory to DNSResourceRecord\n");
	}
	tmp->name=(char *)malloc(sizeof(char)*(name_len+1));
	//把host_name copy 到tmp->name 中来
	memcpy(tmp->name,host_name,name_len+1);
	log_debug(log_level_global,"host name copied to tmp->name\n");
	
	//ntohs:network to host in short(2 bytes)
	//ntohl:...                long(4 bytes)
	//msg[msg_offset] why not?
	tmp->type=ntohs(*(uint16_t *)(msg+msg_offset));
	msg_offset+=2;
	tmp->net_class=ntohs(*(uint16_t *)(msg+msg_offset));
	msg_offset+=2;
	tmp->ttl=ntohl(*(uint32_t *)(msg+msg_offset));
	msg_offset+=4;
	data_len=ntohs(*(uint16_t *)(msg+msg_offset));
	msg_offset+=2;
	log_debug(log_level_global,"type=%d, class=%d,ttl=%d,rdata_len=%d\n",tmp->type,tmp->net_class,tmp->ttl,data_len);
	
	if(tmp->type==5){//CNAME
	
		tmp->rdata=(uint8_t *)malloc(sizeof(uint8_t)*(data_len+1));
		int tmp_offset=0;
		SecureZeroMemory(tmp->rdata,data_len);
		parse_host_name(msg,&msg_offset,tmp->rdata,&tmp_offset);
		msg_offset-=data_len;
		log_debug(log_level_global,"CNAME type,rdata=%s with len %d\n",tmp->rdata,data_len);
	}
	else if(tmp->type==1){//A,32 bits,4 bytes
		tmp->rdata=(uint8_t *)malloc(20);
		sprintf(tmp->rdata,"%d.%d.%d.%d",msg[msg_offset],msg[msg_offset+1],msg[msg_offset+2],msg[msg_offset+3]);
		log_debug(log_level_global,"A type, ipv4:%s\n",tmp->rdata);
	}
	else if(tmp->type==28){//AAAA,128 bits,16 bytes.
		DWORD ipbufferlength = 46;
		tmp->rdata=(uint8_t *)malloc(ipbufferlength);
		uint8_t *t=msg+msg_offset;
		sprintf(tmp->rdata,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",t[0],t[1],t[2],t[3],t[4],t[5],t[6],t[7],t[8],t[9],t[10],t[11],t[12],t[13],t[14],t[15]);
		log_debug(log_level_global,"AAAA type, ipv6:%s\n",tmp->rdata);
	}
		
	*ret_offset=msg_offset+data_len;
	*rr=tmp;
	log_debug(log_level_global,"successfully parsed rr, complete at %d\n",*ret_offset);
	return 0;
}

int parse_rr_section(uint8_t *msg,int len,unsigned short *ret_offset,packet_Information *pac){
	log_debug(log_level_global,"parsing rr section at offset %us...\n",*ret_offset);
	int a_cnt=pac->ancnt;
	unsigned short msg_offset=*ret_offset;
	while(a_cnt--){
		log_debug(log_level_global,"parsing the %d rr at %d\n",a_cnt,msg_offset);
		DNSResourceRecord* newRR=NULL;
		parse_resource_record(msg,&msg_offset,&newRR);
		if(newRR==NULL){
			log_err(log_level_global,"failed to malloc memory for new DNSResourceRecord\n");
			return 1;
		}
		newRR->next=pac->rr_head;
		pac->rr_head=newRR;
	}
	*ret_offset=msg_offset;
	log_debug(log_level_global,"succesfully parsed rr section, complete at %d\n",*ret_offset);
	return 0;
}

DNSQuestion* create_question(uint8_t *host_name,short type,short net_class){
	DNSQuestion* question = (DNSQuestion*)malloc(sizeof(DNSQuestion));
	if(question==NULL){
		log_err(log_level_global,"failed to malloc memory for a new DNSQuestion\n");
	}
	else{
		question->host_name=host_name;
		question->host_type=type;
		question->net_class=net_class;
		question->next=NULL;
	}
	return question;
}
/*
[in] byte array to be parsed
[out] the length of the question section
[out] parsed result
*/
int parse_question(uint8_t *msg,unsigned short *ret_offset,DNSQuestion **question){
	unsigned short msg_offset=*ret_offset;
	char host_name[MAX_HOST_NAME];
	SecureZeroMemory(host_name,MAX_HOST_NAME);
	int name_offset=0;
	parse_host_name(msg,&msg_offset,host_name,&name_offset);
	
	char *shrinked_host_name=(char*)malloc(sizeof(char)*(name_offset+1));
	if(shrinked_host_name==NULL){
		log_err(log_level_global,"failed to malloc memory for shrinked_host_name with len %d\n",name_offset+1);
		return 1;
	}
	memcpy(shrinked_host_name,host_name,name_offset+1);
	*question = create_question(shrinked_host_name,ntohs(*(uint16_t *)(msg+msg_offset)),ntohs(*(uint16_t *)(msg+msg_offset+2)));
	if(*question==NULL){
		log_err(log_level_global,"failed to malloc memory for a new DNSQuestion\n");
		return 1;
	}
	msg_offset+=4;
	*ret_offset=msg_offset;
	
	log_debug(log_level_global,"parse complete at %d, parse result is: %s,%s,%s\n",*ret_offset,(*question)->host_name,(*question)->host_type==1?"A":((*question)->host_type==5?"CNAME":((*question)->host_type==28?"AAAA":"UNKNOWN TYPE")),\
		(*question)->net_class==1?"INTERNET":"UNKNOWN CLASS");
	return 0;
}
int parse_questions_sections(uint8_t *msg,int len,unsigned short* ret_offset,packet_Information *pac){
	log_debug(log_level_global,"parse question sections at %d\n",*ret_offset);
	int q_cnt=pac->qdcnt;
	unsigned short msg_offset=*ret_offset;
	while(q_cnt--){
		log_debug(log_level_global,"parse %d question at %d\n",q_cnt,msg_offset);
		DNSQuestion* new_question=NULL;
		/*
		DNSQuestion* new_question=(DNSQuestion*) malloc(sizeof(DNSQuestion*));
		parse_question(msg,&msg_offset,new_question);
		*/
		parse_question(msg,&msg_offset,&new_question);
		if(new_question==NULL){
			log_err(log_level_global,"parse_question failed due to a failure in mallocing memory");
			return 1;
		}
		new_question->next=pac->question_head;
		pac->question_head=new_question;
	}
	*ret_offset=msg_offset;
	log_debug(log_level_global,"successfully parsed question sections, complete at %d\n",*ret_offset);
}
int parse_Dns_Message(uint8_t* msg,int len,packet_Information *pac){
	log_debug(log_level_global,"parsing dns message\n");
	if(len<DNSHEADER_MINSIZE){
		log_err(log_level_global,"dns_message's head is too short, failed to parse\n");
		return 1;
	}
	unsigned short msg_offset=sizeof(DNSHeader);
	int q_cnt=0;
	//parse header
	DNSHeader *header_ptr=(DNSHeader*)msg;
	DNSQuestion* question_tail=NULL;
	pac->question_head=NULL;
	pac->packet_id=GET_ID(header_ptr);
	pac->packet_type=GET_QR(header_ptr);
	pac->query_type=GET_OPCODE(header_ptr);
	pac->recursion_desired=1;
	pac->qdcnt=GET_QDcnt(header_ptr);
	pac->ancnt=GET_ANcnt(header_ptr);
	log_debug(log_level_global,"parsed head: id=%d, %s,%s,%s,qdcnt=%d,ancnt=%d\n",pac->packet_id,pac->packet_type?"query response":"query",\
		pac->query_type==1?"standard query":(pac->query_type==2?"inverse_query":"unknown"),pac->recursion_desired?"recursion disired":"recursion not disired",pac->qdcnt,pac->ancnt);
	
	
	parse_questions_sections(msg,len,&msg_offset,pac);
	log_debug(log_level_global,"question section parsed\n");
	
	
	if(GET_QR(header_ptr)){
		parse_rr_section(msg,len,&msg_offset,pac);
		log_debug(log_level_global,"resource_records parsed\n");
	}
	return 0;
}