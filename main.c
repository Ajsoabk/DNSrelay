#include"DNSpacket.h"
#include"DNSparser.h"
#include"DNSsocket.h"
#include<synchapi.h>
#include<Windows.h>

int main(int argc, char **argv){
	
	int flag=0;
	if(!initilization()){
		while(!my_recv_dns_msg()){
		}
		if(cleanup_All()){
			flag=1;
		}
	}
	else {
		flag=1;
	}
	return flag;
}
/*

*/
