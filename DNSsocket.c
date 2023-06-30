#include<WinSock2.h>
#include"DNSsocket.h"
#include<stdio.h>
#include<string.h>
#include"DNSpacket.h"
#include<Windows.h>
#include"DNSparser.h"
#include"DNScache.h"
#include"Debugger.h"
#include"DNSSerilizer.h"
#include"PendingQuery.h"

SOCKET localDNSSocket;
char dns_server_addr[100]="10.3.9.44";
int my_close_socket(SOCKET soc){
	int nResult = closesocket(soc);
	if(nResult==SOCKET_ERROR){
		printf("closesocket failed with error %d\n",WSAGetLastError());
	}
	return nResult;
}
int cleanup_All(){
	int ret=(my_close_socket(localDNSSocket)==SOCKET_ERROR);
	WSACleanup();
	return ret;
}
	
int create_Socket(SOCKET *ret){
	*ret = INVALID_SOCKET;
	*ret = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(*ret == INVALID_SOCKET){
		printf("socket failed with error: %d\n", WSAGetLastError());
		return 1;
	}
	return 0;
}
struct sockaddr_in get_addr(int port,unsigned long ip){
	struct sockaddr_in destAddr;
	destAddr.sin_family = AF_INET;
	destAddr.sin_port = htons(port);
	destAddr.sin_addr.s_addr = ip;
	return destAddr;
}
struct sockaddr_in get_local_addr(int port){
	return get_addr(port,htonl(INADDR_ANY));
}
struct sockaddr_in get_loop_addr(int port){
	return get_addr(port,inet_addr("127.0.0.1"));
}
struct sockaddr_in get_server_addr(){
	return get_addr(53,inet_addr(dns_server_addr));
}

int bind_Socket(SOCKET ret,int port){
	log_debug(log_level_global,"bind to %d of local machine",port);
	struct sockaddr_in localDelayAddr=get_local_addr(53);
	int nResult = bind(ret, (SOCKADDR*)&localDelayAddr,sizeof(localDelayAddr));
	if(nResult!= 0){
		log_err(log_level_global,"bind failed with error %d\n",WSAGetLastError());
		return 1;
	}
	return 0;
}
int create_And_Bind(SOCKET *ret,int port){
	if(create_Socket(ret)){
		return 1;
	}
	if(bind_Socket(*ret,port)){
		closesocket(*ret);
		return 1;
	}
	return 0;
}
int initilization(){
	
	WSADATA wsaData;
	int nResult = WSAStartup(MAKEWORD(2,2),&wsaData);
	if(nResult!=0){
		printf("WSAStartup failed with code %d\n",nResult);
		return 1;
	}
	log_debug(log_level_global,"successfully start WSA\n");
	if(create_And_Bind(&localDNSSocket,53)){
		WSACleanup();
		return 1;
	}
	return 0;
}
int my_send_to(char *dataFrame,int dfsize,SOCKADDR *destAddr){
	int nResult=sendto(localDNSSocket,dataFrame,dfsize,0,destAddr, sizeof (*destAddr));
	if (nResult == SOCKET_ERROR) {
		printf("sendto failed with error: %d\n", WSAGetLastError());
		return 1;
	}
	return 0;
}
	
int my_send_to_port(int port,char *buf,int len){
	struct sockaddr_in addr=get_loop_addr(port);
	return my_send_to(buf,len,(SOCKADDR*)&addr);
}
int my_send_to_server(char *buf,int len){
	struct sockaddr_in addr=get_server_addr();
	return my_send_to(buf,len,(SOCKADDR*)&addr);
}

int has_debug_msg(packet_Information *pac){
	if(pac!=NULL){
		DNSQuestion* qptr=pac->question_head;
		while(qptr!=NULL){
			if(strcmp(qptr->host_name,"debug")==0){
				return 1;
			}
			qptr=qptr->next;
		}
	}
	return 0;
}
int has_msg(packet_Information *pac,char *str){
	if(pac!=NULL){
		DNSQuestion* qptr=pac->question_head;
		while(qptr!=NULL){
			if(strcmp(qptr->host_name,str)==0){
				return 1;
			}
			qptr=qptr->next;
		}
	}
	return 0;
}

char* block_address(packet_Information *packet,int ret_val){
    char* block=malloc(sizeof(64));
    FILE *file = fopen("DNSrelay.txt", "r");
    if (file == NULL) {
        log_err(log_level_global, "Failed to open DNSrelay file\n");
        ret_val = 1;
    }
    else {
        //log_err(log_level_global,"BLOCK!!!\n");
        char line[100];
        char domain[100];
        while (fgets(line, sizeof(line), file)) {
            sscanf(line, "%*s %s", domain);
                if (strcmp(packet->question_head->host_name,domain)==0&&packet->query_type==0){
                    //printf("domain is %s\n", domain);
                    //printf("host name is %s\n", packet->question_head->host_name);
                    block="0.0.0.0";
                    log_err(log_level_global,"no such name\n");
                    return block;
                }
        }
        fclose(file);
    }
    return block;
}

int my_recv_dns_msg(){
	packet_Information packet_info;
	packet_Information *packet=&packet_info;
	ZeroMemory((void*)&packet_info,sizeof(packet_info));
	int ret_val=0;
	
	uint8_t RecvBuf[1024];
	int BufLen=1024;
	ZeroMemory(RecvBuf,BufLen);
	struct sockaddr_in SenderAddr;
	int SenderAddrSize = sizeof (SenderAddr);
	log_info(log_level_global,"listening on the port 53...\n");
	int recvBytesCnt=recvfrom(localDNSSocket,RecvBuf, BufLen, 0, (SOCKADDR *)&SenderAddr, &SenderAddrSize);
	if(recvBytesCnt==SOCKET_ERROR){
		log_err(log_level_global,"recvfrom failed with error %d\n",WSAGetLastError());
		ret_val=1;
	}
	else {
		sprintf(packet->source_ip,"%s",inet_ntoa(SenderAddr.sin_addr));
		packet->source_port=htons(SenderAddr.sin_port);
		log_info(log_level_global,"receive a packet from %s:%d\n",packet->source_ip,packet->source_port);
		parse_Dns_Message(RecvBuf,recvBytesCnt,packet);
		if(packet->packet_type){//Response
			int recv_port=pop_by_id(packet->packet_id);
			if(recv_port==-1){
				log_err(log_level_global,"cannot find the pending query with id %d\n",packet->packet_id);
				ret_val=1;
			}
			else{
				if(my_send_to_port(recv_port,RecvBuf,recvBytesCnt)){
					log_err(log_level_global,"failed to send to the port:%d\n",recv_port);
					ret_val=1;
				}else{
					cache_response(packet);
					log_info(log_level_global,"successfully send dns packet %d to %s:%d\n",packet->packet_id,"127.0.0.1",recv_port);
				}
			}
		}
		else{
            //定义一个会返回0.0.0.0的函数
			//check if there are any debug message
			if(has_debug_msg(packet)){
				log_level_global=LOG_LEVEL_ALL;
				log_debug(log_level_global,"switch to debug mode\n");
			}
			else if(has_msg(packet,block_address(packet,ret_val))){
                int len=0;
                packet_Information err_packet;
                SecureZeroMemory((void*)&err_packet,sizeof(err_packet));
                err_packet.packet_id=packet->packet_id;
                err_packet.rcode=3;
                err_packet.packet_type=1;//Response;
                uint8_t SendBuf[1024];
                if(serialize_packet(&err_packet,SendBuf,&len)){
                    log_debug(log_level_global,"failed to serialize\n");
                    ret_val=1;
                }
                else{
                    my_send_to_port(packet->source_port,SendBuf,len);
                }
            }
                /*
                逐行读一个静态表，table.txt
                判断packet->question_head->host_name是否等于当前行的域名
                如果相等
                    组装一个rcode=3的错误dns包
                    发送回去
                */
				/*
				DNSResourceRecord* rrptr=(DNSResourceRecord*)malloc(sizeof(DNSResourceRecord*));
				rrptr->name=(char *)malloc(sizeof("0.0.0.0"));
				strcpy(rrptr->name,"0.0.0.0");
				rrptr->type=1;
				rrptr->net_class=1;
				rrptr->rdata
				*/


			else{

				push_in_pool(packet->packet_id,packet->source_port);
				log_debug(log_level_global,"query with id %d , port %d is pending for response\n",packet->packet_id,packet->source_port);
				if(my_send_to_server(RecvBuf,recvBytesCnt)){
					log_err(log_level_global,"failed to send query to server\n");
					ret_val=1;
				}
				else{
					log_debug(log_level_global,"successfully send query %d to server\n",packet->packet_id);
				}
			}
		}
	}
	clean_up_packet(packet);
	log_debug(log_level_global,"complete \n\n");
	return 0;
}
