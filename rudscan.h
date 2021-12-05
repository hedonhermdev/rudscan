// ----- (begin) library includes -----
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
// ----- (end) library includes -----

// ----- (begin) Hosts -----
typedef struct Ports {
    uint16_t* list;
    size_t size;
    size_t cap;
} Ports;

typedef struct Host {
    struct sockaddr* addr;
    Ports ports; 
    bool online;
} Host;

typedef struct Hosts {
    Host* list; 
    size_t size;
    size_t cap;
} Hosts;

Ports new_ports(size_t cap);
void push_port(Ports *p, uint16_t port);
Host new_host(uint32_t addr);
Hosts new_hosts(size_t cap);
void push_host(Hosts* hosts, Host h);
void free_hosts(Hosts* h);
Hosts* hosts_from_cidr(char* cidr, Hosts* hosts);
// ----- (end) Hosts -----

// ----- (begin) icmp scanning -----
int getrawsocket();
uint16_t in_cksum(uint16_t *addr, size_t len);
void makeicmppacket(struct icmp* buf);
int checkhost(int sockfd, char* sendbuf, char* recvbuf, struct sockaddr* host);
int mark_active_hosts(Hosts* hosts);
// ----- (end) icmp scanning -----

// ----- (begin) port scanning -----
int tcp_scan(Host *h);
int udp_scan(Host *h);
// ----- (end) port scanning -----
