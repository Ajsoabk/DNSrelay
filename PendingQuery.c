#include<stdlib.h>
#include<stddef.h>
typedef struct Pending_Query{
	int id;
	int port;
	struct Pending_Query* next;
}Pending_Query;
Pending_Query *head;
int initialize_pool(){

}
int push_in_pool(int id,int port){
	Pending_Query *query_ptr=(Pending_Query *)malloc(sizeof(Pending_Query));
	query_ptr->id=id;
	query_ptr->port=port;
	query_ptr->next=head;
	head=query_ptr;
}
int pop_by_id(int id){
	int ret=-1;
	Pending_Query *query_ptr=head;
	Pending_Query *previous_ptr=NULL;
	while(query_ptr!=NULL){
		if(query_ptr->id==id){
			ret=query_ptr->port;
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
	return ret;
}
int destroy_pool(){
	Pending_Query* prev;
	while(head!=NULL){
		prev=head;
		head=head->next;
		free(prev);
	}
}