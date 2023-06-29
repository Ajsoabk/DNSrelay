//
// Created by 86187 on 2023/6/29.
//

#include "DNScache.h"
#include<stdlib.h>
#include<stdio.h>
#include <stdint.h>
#include <string.h>
#include<WinSock2.h>
#include<ws2tcpip.h>
extern int debug_level;

DNSRR *head = NULL;
int capacity = 0;
int size = 0;

void printCache() {
    DNSRR *current = head;
    while (current != NULL) {
        printf("rName: %s, rType: %d, ttl: %d, rData: %s\n", current->rName, current->rType, current->ttl, current->rData);
        current = (DNSRR *) current->next;
    }
}
void add_rr(char *rName, uint16_t rType, uint32_t ttl, char *rData) {
    DNSRR *newRecord = (DNSRR *)malloc(sizeof(DNSRR));
    newRecord->rName = strdup(rName);
    newRecord->rType = rType;
    newRecord->rClass = 0; // Assuming rClass is not used in this implementation
    newRecord->ttl = ttl;
    newRecord->rdLen = strlen(rData);
    newRecord->rData = strdup(rData);
    newRecord->next = NULL;
    if (size == 0) {
        head = newRecord;
        size++;
    } else {
        DNSRR *current = head;
        DNSRR *prev = NULL;
        while (current != NULL) {
            if (strcmp(current->rName, rName) == 0 && current->rType == rType) {
                // Record already exists in cache, update its values
                current->ttl = ttl;
                current->rdLen = strlen(rData);
                current->rData = strdup(rData);
                return;
            }
            prev = current;
            current = (DNSRR *) current->next;
        }
        if (size == capacity) {
            // Cache is full, remove the least recently used record (head)
            DNSRR *temp = head;
            head = (DNSRR *) head->next;
            free(temp->rName);
            free(temp->rData);
            free(temp);
            size--;
        }
        // Add the new record to the head of the cache
        newRecord->next = (struct DNSRR *) head;
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