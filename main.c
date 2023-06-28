#include"DNSpacket.h"
#include"DNSparser.h"
#include"DNSsocket.h"
#include<synchapi.h>
#include<Windows.h>

int debug_level=2;
int main(int argc, char **argv){
	int flag=0;
	if(!initilization()){
		packet_Information packet_info;
		ZeroMemory((void*)&packet_info,sizeof(packet_info));
		while(!my_recv_dns_msg(&packet_info)){
		}
		if(cleanup_All()){
			flag=1;
		}
	}
	else flag=1;
	return flag;
}