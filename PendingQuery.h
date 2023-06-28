#ifndef PENDINGQUERY_H
#define PENDINGQUERY_H
int push_in_pool(int id,int port);
int pop_by_id(int id);
int destroy_pool();
#endif