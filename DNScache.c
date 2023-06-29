#include <stdio.h>
#include "Debugger.h"
#include "DNSpacket.h"
#include "DNScache.h"
#include<stdlib.h>
#include <stdint.h>
#include <string.h>

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
		log_debug(log_level_global,"successfully cached an rr with type=%d,ttl=%d,name=%s,rdata=%s\n",rrptr->type,rrptr->ttl,rrptr->name,rrptr->rdata);
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
        add_rr(rrptr);
		rrptr=rrptr->next;
	}
	log_debug(log_level_global,"successfully cached response with id %d\n",pac->packet_id);
	return 0;
}

void add_rr(DNSResourceRecord *rrptr) {
    DNSResourceRecord *head = NULL;
    int capacity = 100000;
    int size = strlen(cache_file);//文件大小

    DNSResourceRecord *newRecord = (DNSResourceRecord *)malloc(sizeof(DNSResourceRecord));
    newRecord->name = strdup(rrptr->name);
    newRecord->type = rrptr->type;
    newRecord->ttl = rrptr->ttl;
    newRecord->rdata = rrptr->rdata;
    newRecord->next = NULL;
    if (size == 0) {
        head = (DNSResourceRecord *) newRecord;
        size++;
    } else {
        DNSResourceRecord *current = head;
        DNSResourceRecord *prev = NULL;
        while (current != NULL) {
            if (strcmp(current->name, rrptr->name) == 0 && current->type == rrptr->type) {
                // Record already exists in cache, update its values
                current->ttl = rrptr->ttl;
                current->rdata = rrptr->rdata;
                return;
            }
            prev = current;
            current = (DNSResourceRecord *) current->next;
        }
        if (size == capacity) {
            // Cache is full, remove the least recently used record (head)
            DNSResourceRecord *temp = head;
            head = (DNSResourceRecord *) head->next;
            free(temp->name);
            free(temp->rdata);
            free(temp);
            size--;
        }
        // Add the new record to the head of the cache
        newRecord->next = (struct DNSResourceRecord *) head;
        head = newRecord;
        size++;
    }
}
//int main() {
//    capacity = 3; // Set the capacity of the cache
//    add_rr("example.com", 1, 3600, "192.168.1.1");
//    add_rr("google.com", 1, 1800, "8.8.8.8");
//    add_rr("facebook.com", 1, 7200, "31.13.65.1");
//    add_rr("example.com", 1, 300, "192.168.1.2"); // Update existing record
//    printCache();
//    return 0;
//}