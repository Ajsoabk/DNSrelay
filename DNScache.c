#include <stdio.h>
#include "Debugger.h"
#include "DNSpacket.h"
#include "DNScache.h"
#include<stdlib.h>
#include <time.h>
#include"Debugger.h"
#include <stdint.h>
#include <string.h>
time_t last_flush_time=0;
DNSRR* cache_head;
DNSRR* cache_tail;
int list_len=0;
int cache_capacity=10;
char cache_file[]="cache.txt";
int get_capacity(){
	return cache_capacity;
}

void initialize_cache(){
	
	last_flush_time = time(NULL);// get current time;
}
DNSRR* get_head_cache(){
	return cache_head;
}
char * get_cache_name(DNSRR *c_ptr){
	if(c_ptr==NULL){
		log_err(log_level_global,"the cache pointer is NULL, failed to get name of it\n");
		return NULL;
	}
	return c_ptr->name;
}
void free_RR(DNSRR* rr){
	if(rr!=NULL){
		if(rr->name!=NULL){
			free(rr->name);
			rr->name=NULL;
		}
		if(rr->rdata!=NULL){
			free(rr->rdata);
			rr->rdata=NULL;
		}
		free(rr);
		rr=NULL;
	}
	else{
		log_warn(log_level_global,"attemping to free a NULL space\n");
	}
	return;
}

int shrink_cache(){
	log_warn(log_level_global,"shrinking cache...\n");
	DNSRR *r_ptr=cache_head;
	cache_head=cache_head->next;
	if(cache_head==NULL){
		cache_tail=NULL;
	}
	free_RR(r_ptr);
	list_len--;
	r_ptr=NULL;
	log_debug(log_level_global,"cache shrinked successfully\n");
}
void set_capacity(int new_capacity){
	while(list_len>new_capacity){
		shrink_cache();
	}
	log_debug(log_level_global,"cache_capacity is set from %d to %d\n",cache_capacity, new_capacity);
	cache_capacity=new_capacity;
}
void flush_expired_cache(){
	log_debug(log_level_global,"cache before flush:\n");
	print_cache_debug();
	DNSRR* c_ptr=cache_head;
	DNSRR* prev_ptr=NULL;
	time_t now_time=time(NULL);
	while(c_ptr!=NULL){
		if(c_ptr->ttl<=now_time-last_flush_time){
			log_debug(log_level_global,"cache(%s,%s,%d) expired with ttl %d\n",c_ptr->name,c_ptr->rdata,c_ptr->type,c_ptr->ttl);
			
			log_debug(log_level_global,"1:\n");
			if(prev_ptr!=NULL)
				log_debug(log_level_global,"prev:%p\n",prev_ptr);
			log_debug(log_level_global,"now:%p\n",c_ptr);
			if(cache_head!=NULL)
				log_debug(log_level_global,"head:%p\n",cache_head);
			if(cache_tail!=NULL)
				log_debug(log_level_global,"head:%p\n",cache_tail);
			
			
			if(prev_ptr!=NULL){
				prev_ptr->next=c_ptr->next;
			}
			else{
				cache_head=c_ptr->next;
			}
			
			log_debug(log_level_global,"2:\n");
			if(prev_ptr!=NULL)
				log_debug(log_level_global,"prev:%p\n",prev_ptr);
			log_debug(log_level_global,"now:%p\n",c_ptr);
			if(cache_head!=NULL)
				log_debug(log_level_global,"head:%p\n",cache_head);
			if(cache_tail!=NULL)
				log_debug(log_level_global,"head:%p\n",cache_tail);
			
			if(c_ptr==cache_tail){
				cache_tail=prev_ptr;
			}
			
			
			log_debug(log_level_global,"3:\n");
			if(prev_ptr!=NULL)
				log_debug(log_level_global,"prev:%p\n",prev_ptr);
			log_debug(log_level_global,"now:%p\n",c_ptr);
			if(cache_head!=NULL)
				log_debug(log_level_global,"head:%p\n",cache_head);
			if(cache_tail!=NULL)
				log_debug(log_level_global,"head:%p\n",cache_tail);
			log_debug(log_level_global,"waiting for free");
			free_RR(c_ptr);
			
			c_ptr=prev_ptr==NULL?cache_head:prev_ptr->next;
			list_len--;
			log_debug(log_level_global,"rr is free~");
		}
		else{
			c_ptr->ttl-=now_time-last_flush_time;
			prev_ptr=c_ptr;
			c_ptr=c_ptr->next;
		}
	}
	last_flush_time=now_time;
	
	log_debug(log_level_global,"cache after flush:\n");
	print_cache_debug();
}
DNSRR * find_cache_with(char *name,int type,int class){
	log_debug(log_level_global,"finding cache with name %s,type %d, class %d\n...",name,type,class);
	flush_expired_cache();
	print_cache_debug();
	DNSRR* c_ptr=cache_head;
	while(c_ptr!=NULL){
		if(strcmp(c_ptr->name,name)==0&&c_ptr->type==type&&c_ptr->net_class==class){
			log_debug(log_level_global,"successfully find an identical cache\n");
			return c_ptr;
		}
		log_debug(log_level_global,"can't find cache in this loop\n");
		c_ptr=c_ptr->next;
	}
	return NULL;
}
DNSResourceRecord* find_in_cache(DNSQuestion* q_ptr){
	log_debug(log_level_global,"finding matched cache...\n");
	if(q_ptr==NULL){
		log_warn(log_level_global,"question pointer is NULL, failed to find in cache\n");
		return NULL;
	}
	DNSRR* r_ptr=find_cache_with(q_ptr->host_name,q_ptr->host_type,q_ptr->net_class);
	if(r_ptr==NULL){
		log_debug(log_level_global,"no matched cache\n");
		return NULL;
	}
	log_debug(log_level_global,"loading a DNSResourceRecord object\n");
	DNSResourceRecord* ret_ptr=(DNSResourceRecord*)malloc(sizeof(DNSResourceRecord));
	if(ret_ptr==NULL){
		log_warn(log_level_global,"failed to malloc memory for DNSResourceRecord\n");
		return NULL;
	}
	ret_ptr->type=r_ptr->type;
	ret_ptr->net_class=r_ptr->net_class;
	ret_ptr->ttl=r_ptr->ttl;
	ret_ptr->name=strdup(r_ptr->name);
	ret_ptr->rdata=strdup(r_ptr->rdata);
	ret_ptr->next=NULL;
	//log_debug(log_level_global,"pointer of DNSRR:%s(%p) %s (%p)\npointer of ResourceRecord:%s(%p) %s(%p)\n",r_ptr->name,r_ptr->name,r_ptr->rdata,r_ptr->rdata,ret_ptr->name,ret_ptr->name,ret_ptr->rdata,ret_ptr->rdata);
	log_debug(log_level_global,"successfully find in cache\n");
	return ret_ptr;
}
	
/*
add a cache into list
only dealing with list_len,cache_tail and cache_head
*/
void add_RR(DNSRR *r_ptr){
	if(cache_head==NULL){
		cache_head=cache_tail=r_ptr;
		list_len=1;
	}
	else{
		cache_tail->next=r_ptr;
		cache_tail=r_ptr;
		list_len++;
	}
	log_debug(log_level_global,"after adding, the list len is %d\n",list_len);
}
int cache_is_full(){
	return list_len>=cache_capacity;
}
int add_cache(DNSResourceRecord* rrptr){
	log_debug(log_level_global,"adding cache...\n");
	if(rrptr==NULL){
		log_warn(log_level_global,"DNSResourceRecord pointer is NULL, failed to add it into cache\n");
		return 1;
	}
	if(rrptr->ttl==0){
		log_debug(log_level_global,"the ttl of this record is zero, don't need to cache it\n");
		return 0;
	}
	DNSRR* tmp_ptr;
	if((tmp_ptr=find_cache_with(rrptr->name,rrptr->type,rrptr->net_class))!=NULL){
		log_debug(log_level_global,"find an identical cache in the list, updating the ttl to %d",rrptr->ttl);
		tmp_ptr->ttl=rrptr->ttl;
		return 0;
	}
	log_debug(log_level_global,"adding it into cache\n");
	if(cache_is_full()){
		log_debug(log_level_global,"list is full, trying to shrink\n");
		if(shrink_cache()==1){
			log_debug(log_level_global,"failed to shrink\n");
			return 1;
		}
	}
	DNSRR *new_rr=(DNSRR *)malloc(sizeof(DNSRR));
	new_rr->type=rrptr->type;
	new_rr->net_class=rrptr->net_class;
	new_rr->ttl=rrptr->ttl;
	new_rr->name=strdup(rrptr->name);
	new_rr->rdata=strdup(rrptr->rdata);
	new_rr->next=NULL;
	add_RR(new_rr);
	print_cache_debug();
	log_debug(log_level_global,"successfully added a element of cache\n");
	return 0;
}
void print_cache_debug(){
	if(cache_head==NULL){
		log_debug(log_level_global,"cache is empty\n");
		return;
	}
	DNSRR* r_ptr=cache_head;
	while(r_ptr!=NULL){
		log_debug(log_level_global,"%-10d%-10s%-10d%-40s%-40s\n",r_ptr->net_class,r_ptr->type==1?"A":"AAAA",r_ptr->ttl,r_ptr->name,r_ptr->rdata);
		r_ptr=r_ptr->next;
	}
	return;
}
/*
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
*/

int cache_response(packet_Information *pac){
	log_debug(log_level_global,"caching response...\n");
	if(pac==NULL){
		log_err(log_level_global,"the packet pointer is NULL, failed to cache");
		return 1;
	}
	DNSResourceRecord *rrptr=pac->rr_head;
	while(rrptr!=NULL){
		add_cache(rrptr);
		rrptr=rrptr->next;
	}
	print_cache_debug();
	log_debug(log_level_global,"successfully cached response with id %d\n",pac->packet_id);
	return 0;
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