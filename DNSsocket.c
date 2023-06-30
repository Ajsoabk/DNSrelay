#include<WinSock2.h>
#include"DNSsocket.h"
#include<stdio.h>
#include<string.h>
#include"DNSpacket.h"
#include<Windows.h>
#include<unistd.h>
#include"DNSparser.h"
#include"DNScache.h"
#include"Debugger.h"
#include"DNSSerilizer.h"
#include"PendingQuery.h"

SOCKET localDNSSocket;
char dns_server_addr[100]="10.3.9.44";
char block_file_name[100]="DNSrelay.txt";
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
int change_dns_server_name(char *dns_ip){
	//TO-DO:check if dns_ip is valid;
	strcpy(dns_server_addr,dns_ip);
}
void print_help_information(){
	printf("usage:\n");
	printf("\tmain -di\n");
	printf("\tmain -s 10.3.9.44\n");
	printf("Options:\n");
	printf("\t-d\t\tSet the Debug mode , could be followed by i(INFO),w(WARNING),e(ERROR),f(FATAL),o(OFF)\n");
	printf("\t-s\t\tSet the server address\n");
	printf("\t-f\t\tSet the path of blocklist\n");
	printf("\t-c\t\tSet the capacity of cache,default %d\n",get_capacity());
}
int parse_to_int(char *str){
	int ret=0;
	while((*str)!='\0'){
		if((*str)>='0'&&(*str)<='9'){
			ret=ret*10+(*str)-'0';
		}
		else{
			return -1;
		}
		str++;
	}
	return ret;
}
		
int initilization(int argc, char **argv){
	
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
	void initialize_cache();
	int ret=0;
	//设置调试模式（-d），可选参数，默认为INFO，-d后默认为DEBUG
	while ((ret = getopt(argc, argv, "d::s:f:hc:")) != -1)
    {  
		switch(ret){
			case 'd':
				;
				LOG_LEVEL new_level=LOG_LEVEL_ALL;
				if(optarg!=NULL){
					if(*optarg=='i'){
						new_level=LOG_LEVEL_INFO;
					}
					else if(*optarg=='w'){
						
						new_level=LOG_LEVEL_WARN;
					}
					else if(*optarg=='e'){
						new_level=LOG_LEVEL_ERR;
					}
					else if(*optarg=='f'){
						new_level=LOG_LEVEL_FATAL;
					}
					else if(*optarg=='o'){
						new_level=LOG_LEVEL_OFF;
					}
					else{
						log_warn(log_level_global,"-d followed by an invalid argument %s\n",optarg);
					}
				}
				log_level_switch_to(new_level);
				break;
			case 's':
				if(optarg!=NULL){
					change_dns_server_name(optarg);
					log_debug(log_level_global,"server ip address is set to %s\n",optarg);
				}
				else{
					
					log_warn(log_level_global,"-s need to be followed by an argument\n");
				}
				break;
			case 'f':
				if(optarg!=NULL){
					
					FILE *file = fopen(optarg, "r");
					if (file == NULL) {
						log_warn(log_level_global,"failed to open the file %s\n",optarg);
					}
					else{
						strcpy(block_file_name,optarg);
						log_debug(log_level_global,"block file is set to %s\n",optarg);
					}
					fclose(file);
				}
				else{
					
					log_warn(log_level_global,"-f need to be followed by an argument\n");
				}
				break;
			case 'h':
				print_help_information();
				return 1;
			case 'c':
				;
				int new_c=parse_to_int(optarg);
				if(new_c>=0){
					set_capacity(new_c);
				}
				else{
					log_warn(log_level_global,"invalid argument for -c with %s\n",optarg);
				}
				break;
			default:
				log_warn(log_level_global,"Invalid argument, using -h to get help\n");
				break;
		}	
		/*
        printf("ret = %c\t\t", ret);
        printf("optarg = %s\t\t", optarg);
        printf("optind = %d\t\t", optind);
        printf("argv[optind] = %s\n", argv[optind]);
		*/
		
    }  
	return 0;
}
int my_send_to(char *dataFrame,int dfsize,SOCKADDR *destAddr){
	int nResult=sendto(localDNSSocket,dataFrame,dfsize,0,destAddr, sizeof (*destAddr));
	if (nResult == SOCKET_ERROR) {
		printf("sendto failed with error: %d\n", WSAGetLastError());
		return 1;
	}
	log_debug(log_level_global,"successfully send a message\n");
	return 0;
}
	
int my_send_to_port(int port,char *buf,int len){
	log_debug(log_level_global,"sending message to %d\n",port);
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
/*
[in]目标端口
[in]首部id
*/
int send_err_msg_to_port(int port,int id){
	log_debug(log_level_global,"Sending error message to port %d with id %d\n",port,id);
	int len=0;
	packet_Information err_packet;
	SecureZeroMemory((void*)&err_packet,sizeof(err_packet));
	err_packet.packet_id=id;
	err_packet.rcode=3;
	err_packet.packet_type=1;//Response;
	uint8_t SendBuf[1024];
	SecureZeroMemory(SendBuf,1024);
	if(serialize_packet(&err_packet,SendBuf,&len)){
		log_debug(log_level_global,"failed to serialize\n");
		return 1;
	}
	log_debug(log_level_global,"serialized into a byte array of length %d\n",len);
	my_send_to_port(port,SendBuf,len);
	log_debug(log_level_global,"successfully send a error message\n");
	return 0;
}

int send_cached_rr_to_port(DNSResourceRecord* r_ptr,packet_Information *pac){
	log_debug(log_level_global,"Sending cached response to port %d with id %d\n",pac->source_port,pac->packet_id);
	packet_Information cache_packet;
	SecureZeroMemory(&cache_packet,sizeof(cache_packet));
	cache_packet.packet_id=pac->packet_id;
	cache_packet.packet_type=1;
	cache_packet.qdcnt=pac->qdcnt;
	cache_packet.question_head=pac->question_head;
	pac->question_head=NULL;
	pac->qdcnt=0;
	
	uint8_t SendBuf[1024];
	SecureZeroMemory(SendBuf,1024);
	cache_packet.rr_head=r_ptr;
	cache_packet.ancnt=1;
	int len=0;
	if(serialize_packet(&cache_packet,SendBuf,&len)){
		log_err(log_level_global,"failed to serialize cached rr\n");
		return 1;
	}
	
	log_debug(log_level_global,"serialized into a byte array of length %d\n",len);
	if(my_send_to_port(pac->source_port,SendBuf,len)){
		log_debug(log_level_global,"failed to send cached msg to %d\n",pac->source_port);
	}
	else{
		log_debug(log_level_global," Successfully send cached response\n");
	}
	clean_up_packet(&cache_packet);
	return 0;
}
int block_address(packet_Information *packet,int ret_val){
	int block=0;
    FILE *file = fopen(block_file_name, "r");
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
					block=1;
                    log_err(log_level_global,"no such name\n");
                }
        }
    }
    fclose(file);
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
			if(has_msg(packet,"debug")){
				log_level_switch_to(LOG_LEVEL_ALL);
				if(send_err_msg_to_port(packet->source_port,packet->packet_id)){
					ret_val=1;
				}
			}
			else if(has_msg(packet,"info")){
				log_level_switch_to(LOG_LEVEL_INFO);
				if(send_err_msg_to_port(packet->source_port,packet->packet_id)){
					ret_val=1;
				}
			}
			else if(has_msg(packet,"warn")){
				
				log_level_switch_to(LOG_LEVEL_WARN);
				if(send_err_msg_to_port(packet->source_port,packet->packet_id)){
					ret_val=1;
				}
			}
			else if(has_msg(packet, "error")){
				log_level_switch_to(LOG_LEVEL_ERR);
				if(send_err_msg_to_port(packet->source_port,packet->packet_id)){
					ret_val=1;
				}
			}
			else if(has_msg(packet, "fatal")){
				log_level_switch_to(LOG_LEVEL_FATAL);
				if(send_err_msg_to_port(packet->source_port,packet->packet_id)){
					ret_val=1;
				}
			}
			else if(has_msg(packet, "off")){
				log_level_switch_to(LOG_LEVEL_OFF);
				if(send_err_msg_to_port(packet->source_port,packet->packet_id)){
					ret_val=1;
				}
			}
			else if(block_address(packet,ret_val)){
				send_err_msg_to_port(packet->source_port,packet->packet_id);
				
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

            }
			else{
				DNSResourceRecord* cached_rr=find_in_cache(packet->question_head);
				if(cached_rr!=NULL){
					
					log_debug(log_level_global,"using cache to response\n");
					send_cached_rr_to_port(cached_rr,packet);
				}
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
				log_debug(log_level_global,"cache in this loop is:\n");
				print_cache_debug();
			}
		}
	}
	
	clean_up_packet(packet);
	log_debug(log_level_global,"cache after the process of the packet\n");
	print_cache_debug();
	log_debug(log_level_global,"complete \n\n");
	return 0;
}
