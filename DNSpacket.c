#include"DNSpacket.h"
#include<stdlib.h>
void free_question(DNSQuestion* question){
	if(question!=NULL)
		free(question->host_name);
	return ;
}
void free_rr(DNSResourceRecord* rr){
	if(rr!=NULL){
		free(rr->name);
		free(rr->rdata);
	}
	return;
}
void clean_up_packet(packet_Information *pac){
	if(pac==NULL)
		return;
	DNSQuestion *qptr;
	DNSResourceRecord *rrptr;
	
	while(pac->question_head!=NULL){
		qptr=pac->question_head;
		pac->question_head=pac->question_head->next;
		free_question(qptr);
	}
	while(pac->rr_head!=NULL){
		rrptr=pac->rr_head;
		pac->rr_head=pac->rr_head->next;
		free_rr(rrptr);
	}
}
	