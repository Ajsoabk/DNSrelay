#include"DNSpacket.h"
#include<stdio.h>
#include<WinSock2.h>
#include<stdint.h>
#include"Debugger.h"

#define BigLittleSwap16(A)  ((((uint16_t)(A) & 0xff00) >> 8) |(((uint16_t)(A) & 0x00ff) << 8))
/*
把带点号的域名转换成协议里要求的格式，即点号用子域名长度代替
*/
int convert_dot_to_digit(char* host_name,unsigned char *buf,int *len){
	
	char *name_ptr=host_name;
	char *last_place=buf;
	char *buf_ptr=buf+1;
	int label_len=0;
	int offset=1;
	while(*name_ptr!='\0'){
		if(*name_ptr=='.'){
			*last_place=label_len;
			label_len=0;
			last_place=buf_ptr;
			*buf_ptr='.';
		}
		else{
			*buf_ptr=*name_ptr;
			label_len++;
		}
		buf_ptr++;
		offset++;
		name_ptr++;
	}
	*last_place=label_len;
	*buf_ptr=(unsigned char)0;
	*len=offset;
	return 0;
}
/*
把点分十进制的ipv4地址转换成4字节的网络地址
127.0.0.1
01111111 00000000 0000000 00000001
*/
int split_ipv4_by_dots(char *ipv4,unsigned char*buf){
	char *ch_ptr=ipv4;
	uint8_t addr=0,digit=0,buf_offset=0;
	while(*ch_ptr!='\0'){
		if(*ch_ptr>='0'&&*ch_ptr<='9'){
			digit=*ch_ptr-'0';
			addr=addr*10+digit;
		}
		else if(*ch_ptr=='.'){
			buf[buf_offset]=(unsigned char)addr;
			addr=0;
			buf_offset++;
		}
		ch_ptr++;
	}
	buf[buf_offset]=(unsigned char)addr;
	return 0;
	
}
/*
把ipv6的标准地址转换成16字节的网络地址
2a03:2880:f10f:0083:face:b00c:0000:25de
->
2a032880f10f...
*/
int split_ipv6_by_comma(char *ipv6,unsigned char *buf){
	char *ch_ptr=ipv6;
	uint16_t addr=0,digit=0,buf_offset=0;
	while(*ch_ptr!='\0'){
		if(*ch_ptr>='0'&&*ch_ptr<='9'){
			digit=*ch_ptr-'0';
			addr=addr*16+digit;
		}
		else if(*ch_ptr>='a'&&*ch_ptr<='f'){
			digit=*ch_ptr-'a'+10;
			addr=addr*16+digit;
		}
		else if(*ch_ptr>='A'&&*ch_ptr<='F'){
			digit=*ch_ptr-'A'+10;
			addr=addr*16+digit;
		}
		else if(*ch_ptr==':'){
			buf[buf_offset]=(unsigned char)(addr>>8);
			buf[buf_offset+1]=(unsigned char)(addr&0x00ff);
			addr=0;
			buf_offset+=2;
		}
		ch_ptr++;
	}
	buf[buf_offset]=(unsigned char)(addr>>8);
	buf[buf_offset+1]=(unsigned char)(addr&0x00ff);
	return 0;
}
/*
首部序列化
*/
int serialize_dns_head(packet_Information* pac,uint8_t *buf,int *buf_offset){
	log_debug(log_level_global,"serializing the packet head\n");
	DNSHeader new_header;
	DNSHeader *header=&new_header;
	SecureZeroMemory(&header,sizeof(DNSHeader));
	header->ID=BigLittleSwap16(pac->packet_id);
	header->QDcnt=BigLittleSwap16(pac->qdcnt);
	header->ANcnt=BigLittleSwap16(pac->ancnt);
	unsigned short flags=0;
	flags|=((pac->packet_type)&1)<<15;
	flags|=((pac->query_type)&15)<<11;
	flags|=((pac->rcode)&15);
	
	header->flags=BigLittleSwap16(flags);
	memcpy(buf,&header,sizeof(DNSHeader));
	
	log_debug(log_level_global,"Successfully serialized the packet head\n");
	return 0;
}
/*
quesiton序列化
*/
int serialize_question(DNSQuestion* qptr,uint8_t *buf,int *buf_offset){
	log_debug(log_level_global,"serializing question\n");
	if(qptr==NULL){
		log_err(log_level_global,"Question pointer is NULL, failed to serialize\n");
		return 1;
	}
	int offset=0;
	convert_dot_to_digit(qptr->host_name,buf,&offset);
	*((uint16_t*)(buf+offset+1))=BigLittleSwap16(qptr->host_type);
	*((uint16_t*)(buf+offset+3))=BigLittleSwap16(qptr->net_class);
	*buf_offset=offset;
	log_debug(log_level_global,"Successfully serialized question\n");
}
/*
资源记录（rr）序列化
*/
int serialize_rr(DNSResourceRecord* rrptr,uint8_t *buf,int *buf_offset){
	log_debug(log_level_global,"serializing resource record\n");
	if(rrptr==NULL){
		log_err(log_level_global,"Resource Record pointer is NULL,failed to serialize\n");
		return 1;
	}
	else if(rrptr->type!=1&&rrptr->type!=28){
		log_err(log_level_global,"Resource Record type is not supported\n");
		return 1;
	}
	int offset=0;
	convert_dot_to_digit(rrptr->name,buf,&offset);
	*((uint16_t*)(buf+offset+1))=BigLittleSwap16(rrptr->type);
	*((uint16_t*)(buf+offset+3))=BigLittleSwap16(rrptr->net_class);
	*((uint16_t*)(buf+offset+5))=BigLittleSwap16(rrptr->ttl);
	if(rrptr->type==1){
		split_ipv4_by_dots(rrptr->rdata,buf);
		offset+=4;
	}
	else{
		split_ipv6_by_comma(rrptr->rdata,buf);
		offset+=16;
	}
	return 0;
	log_debug(log_level_global," Successfully serialized resource record\n");
}
/*
dns包序列化
*/
int serialize_packet(packet_Information* pac,uint8_t *buf,int *len){
	log_debug(log_level_global,"serializing packet...\n");
	if(pac==NULL){
		log_err(log_level_global,"packet is NULL, failed to serialize\n");
		return 1;
	}
	int offset=0;
	if(serialize_dns_head(pac,buf,&offset)==1){
		log_err(log_level_global,"failed to serialize_dns_head");
		return 1;
	}
	DNSQuestion *qptr=pac->question_head;
	while(qptr!=NULL){
		if(serialize_question(qptr,buf,&offset)==1){
			log_err(log_level_global,"failed to serialize question\n");
			return 1;
		}
		
		qptr=qptr->next;
	}
	log_debug(log_level_global,"Question section serialized.\n");
	
	DNSResourceRecord* rrptr=pac->rr_head;
	while(rrptr!=NULL){
		if(serialize_rr(rrptr,buf,&offset)==1){
			log_err(log_level_global,"failed to serialize Resource Record\n");
			return 1;
		}
		rrptr=rrptr->next;
	}
	log_debug(log_level_global,"Resource record section serialized.\n");
	log_debug(log_level_global,"Successfully serialized a packet into network format\n");
	return 0;
}
/*
int main(int argc, char **argv){
	/*
	//code to test conver_dot_to_digit function
	if(argc!=2){
		return 1;
	}
	char ret[100];
	
	convert_dot_to_digit(argv[1],ret);
	printf("ret:%s\n",ret);
	*/
	
	/*
	//code to test split_ipv4_by_dots function
	if(argc!=2){
		return 1;
	}
	unsigned char ret[4];
	split_ipv4_by_dots(argv[1],ret);
	printf("%ud.%ud.%ud.%ud\n",ret[0],ret[1],ret[2],ret[3]);
	*/
	
	/*
	//code to test split_ipv6_by_comma function
	if(argc!=2){
		return 1;
	}
	unsigned char ret[16];
	split_ipv6_by_comma(argv[1],ret);
	printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",ret[0],ret[1],ret[2],ret[3],ret[4],ret[5],ret[6],ret[7],ret[8],ret[9],ret[10],ret[11],ret[12],ret[13],ret[14],ret[15]);
	return 0;
}

	*/