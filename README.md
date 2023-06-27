# DNSrelay
## Requirement
MinGW 64, gcc 8.1
windows 10

## Execution
gcc main.c DNSparser.c DNSsocket.c -lwsock32 -lws2_32 -o main
main

## Example
DNS server: 10.3.9.45