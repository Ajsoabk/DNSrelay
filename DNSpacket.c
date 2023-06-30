#include"DNSpacket.h"
#include<stdlib.h>
#include"Debugger.h"
#include"DNScache.h"
void free_question(DNSQuestion* question){
	if(question!=NULL){
		free(question->host_name);
		question->host_name=NULL;//防止 double free
	}
	return ;
}
void free_rr(DNSResourceRecord* rr){
	if(rr!=NULL){
		if(rr->name!=NULL){
			free(rr->name);
			rr->name=NULL;
		}
		if(rr->rdata!=NULL){
			free(rr->rdata);
			rr->rdata=NULL;
		}
	}
	return;
}
void clean_up_packet(packet_Information *pac){
	log_debug(log_level_global,"cleaning up packet...\n");

	if(pac==NULL){
		log_debug(log_level_global,"packet is empty, no need to clean\n");
		return;
	}
	log_debug(log_level_global,"with id %d\n",pac->packet_id);
	DNSQuestion *qptr;
	DNSResourceRecord *rrptr;
	
	while(pac->question_head!=NULL){
		qptr=pac->question_head;
		pac->question_head=pac->question_head->next;
		
		log_debug(log_level_global,"freeing question which asks for %s\n",qptr->host_name);
		free_question(qptr);
		
	}
	
	while(pac->rr_head!=NULL){
		rrptr=pac->rr_head;
		pac->rr_head=pac->rr_head->next;
		
		log_debug(log_level_global,"freeing resource record with type %d, name %s, rdata %s\n",rrptr->type,rrptr->name,rrptr->rdata);
		free_rr(rrptr);
	}
	
	log_debug(log_level_global,"packet %d is cleaned up successfully\n",pac->packet_id);
}
	