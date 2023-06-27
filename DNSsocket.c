#include<WinSock2.h>
#include"DNSsocket.h"
#include<stdio.h>
#include"DNSpacket.h"
#include"DNSparser.h"

typedef struct Pending_Query{
	int id;
	int port;
	struct Pending_Query* next;
}Pending_Query;
SOCKET localDNSSocket;
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
	return get_addr(53,inet_addr("10.3.9.45"));
}

int bind_Socket(SOCKET ret,int port){
	printf("bind to %d port of the local machine...\n",port);
	struct sockaddr_in localDelayAddr=get_local_addr(53);
	int nResult = bind(ret, (SOCKADDR*)&localDelayAddr,sizeof(localDelayAddr));
	if(nResult!= 0){
		printf("bind failed with error %d\n",WSAGetLastError());
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

Pending_Query *head=NULL;
int initilization(){
	WSADATA wsaData;
	int nResult = WSAStartup(MAKEWORD(2,2),&wsaData);
	if(nResult!=0){
		printf("WSAStartup failed with code %d\n",nResult);
		return 1;
	}
	printf("Successfully start WSA\n");
	if(create_And_Bind(&localDNSSocket,53)){
		WSACleanup();
		return 1;
	}
	head=NULL;
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
int my_recv_dns_msg(packet_Information *packet){
	
	static char RecvBuf[1024];
	static int BufLen=1024;
	struct sockaddr_in SenderAddr;
	int SenderAddrSize = sizeof (SenderAddr);
	int recvBytesCnt=recvfrom(localDNSSocket,RecvBuf, BufLen, 0, (SOCKADDR *)&SenderAddr, &SenderAddrSize);
	if(recvBytesCnt==SOCKET_ERROR){
		printf("recvfrom failed with error %d\n",WSAGetLastError());
		return 1;
	}
	else {
		sprintf(packet->source_ip,"%s",inet_ntoa(SenderAddr.sin_addr));
		packet->source_port=htons(SenderAddr.sin_port);
		parse_Dns_Message(RecvBuf,recvBytesCnt,packet);
		if(packet->packet_type){//Response
			printf("parsing a response packet with id %d\n",packet->packet_id);
			Pending_Query *query_ptr=head;
			Pending_Query *previous_ptr=NULL;
			int recv_port=-1;
			while(query_ptr!=NULL){
				if(query_ptr->id==packet->packet_id){
					recv_port=query_ptr->port;
					if(previous_ptr!=NULL){
						previous_ptr->next=query_ptr->next;
					}
					else{
						head=NULL;
					}
					
					free(query_ptr);
					break;
				}
				previous_ptr=query_ptr;
				query_ptr=query_ptr->next;
			}
			if(recv_port!=-1){
				if(my_send_to_port(recv_port,RecvBuf,recvBytesCnt)){
					return 1;
				}
				else{
					printf("my_recv_dns_msg:\t\t\tsend a packet to %s:%d with id:%d\n","127.0.0.1",recv_port,packet->packet_id);
				}
			}
		}
		else{
			Pending_Query *query_ptr=(Pending_Query *)malloc(sizeof(Pending_Query));
			query_ptr->id=packet->packet_id;
			query_ptr->port=packet->source_port;
			query_ptr->next=head;
			head=query_ptr;
			if(my_send_to_server(RecvBuf,recvBytesCnt)){
				return 1;
			}
		}
		printf("my_recv_dns_msg:\t\t\treceive a packet from%s:%d with id:%d\n",packet->source_ip,packet->source_port,packet->packet_id);
	}
	return 0;
}
