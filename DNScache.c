#include<stdio.h>
#include"Debugger.h"
#include"DNSpacket.h"
char cache_file[]="cache.txt";
int cache_rr(DNSResourceRecord *rrptr){
	log_debug(log_level_global,"caching resource record...\n");
	if(rrptr==NULL){
		log_err(log_level_global,"the resource record pointer is NULL, failed to cache");
		return 1;
	}
	if(rrptr->ttl==0){
		log_debug(log_level_global,"this resource record should not be cached because the ttl is 0");
	}
	else if(rrptr->type==1||rrptr->type==28){
		FILE *fptr=fopen(cache_file,"a");
		//type ttl name rdata
		if(fptr==NULL){
			log_err(log_level_global,"failed to open cache file %s",cache_file);
			return 1;
		}
		fprintf(fptr,"%s\t\t%d\t\t%s\t\t%s\n",rrptr->type==1?"A":"AAAA",rrptr->ttl,rrptr->name,rrptr->rdata);
		fclose(fptr);
		log_debug(log_level_global,"successfully cached an rr with type=%d,ttl=%d,name=%s,rdata=%s\n",rrptr->type,rrptr->ttl,rrptr->name,rrptr_rdata);
	}
	else{
		log_debug(log_level_global,"this resource record's type(%d) is not supported to cache",rrptr->type);
	}
	return 0;
}
int cache_response(packet_Information *pac){
	log_debug(log_level_global,"caching response...\n");
	if(pac==NULL){
		log_err(log_level_global,"the packet pointer is NULL, failed to cache");
		return 1;
	}
	DNSResourceRecord *rrptr=pac->rr_head;
	while(rrptr!=NULL){
		cache_rr(rrptr);
		rrptr=rrptr->next;
	}
	log_debug(log_level_global,"successfully cached response with id %d\n",pac->packet_id);
	return 0;
}