#include"DNSpacket.h"
#include<stdio.h>
#include<stdint.h>
#include"Debugger.h"
int convert_dot_to_digit(char* host_name,unsigned char *buf){
	char *name_ptr=host_name;
	char *last_place=buf;
	char *buf_ptr=buf+1;
	int label_len=0;
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
		name_ptr++;
	}
	*last_place=label_len;
	*buf_ptr=(unsigned char)0;
	return 0;
}
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
	
int serialize_rr(DNSResourceRecord* rr,uint8_t *buf,int *len){
	if(rr->type==1){
		buf
	}
	else if(rr->type==5){
		
	}
	else if(rr->type==28){
		
	}
}
int serialize_packet(packet_Information* pac,uint8_t *buf,int *len){
	
}