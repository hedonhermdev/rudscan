#include "rudscan.h"

Ports new_ports(size_t cap) {
    Ports p;

    p.list = (uint16_t*) malloc(cap * sizeof(uint16_t));
    p.cap = cap;
    p.size = 0;

    return p;
}

void push_port(Ports *p, uint16_t port) {
    if (p->size >= p->cap) {
        p->list = (uint16_t*) realloc(p->list, 2 * p->cap * sizeof(uint16_t));
        p->cap = 2 * p->cap;
    }
    p->list[p->size++] = port;
}

Host new_host(uint32_t addr) {
    Host h;
    struct in_addr in;
    struct sockaddr_in* sa;

    sa = malloc(sizeof(struct sockaddr_in));

    in.s_addr = htonl(addr);
    sa->sin_family = AF_INET;
    sa->sin_port = 0;
    sa->sin_addr = in;

    h.addr = (struct sockaddr*) sa;
    h.ports = new_ports(4);

    return h;
}

Hosts new_hosts(size_t cap) {
    Hosts h;

    h.list = (Host*) malloc(cap * sizeof(Host));
    h.cap = cap;
    h.size = 0;

    return h;
}

void push_host(Hosts* hosts, Host h) {
    if (hosts->size >= hosts->cap) {
        hosts->list = (Host*) realloc(hosts->list, 2 * hosts->cap * sizeof(Host)); 
        hosts->cap *= 2; 
    }
    hosts->list[hosts->size++] = h;
}


void free_hosts(Hosts* h) {
    for (int i = 0; i < h->size; i++) {
        free(h->list[i].addr);
        free(h->list[i].ports.list);
    }
    free(h);
}

Hosts* hosts_from_cidr(char* cidr, Hosts* hosts) {

    uint8_t a, b, c, d, bits;

    uint32_t ip, mask;

    Host h;

    // FIXME: undefined behavior with invalid cidr
    if (sscanf(cidr, "%hhu.%hhu.%hhu.%hhu/%hhu", &a, &b, &c, &d, &bits) < 5) {
        fprintf(stderr, "iprange: invalid cidr");
        return NULL;
    }

    if (bits > 32) {
        fprintf(stderr, "iprange: invalid cidr");
        return NULL;
    }

    ip = (a << 24UL) | (b << 16UL) | (c << 8UL) | (d);
    mask = (0xFFFFFFFFUL << (32 - bits)) & 0xFFFFFFFFUL;


    uint32_t first_ip, last_ip;

    first_ip = ip & mask;
    last_ip = ip | ~mask;

    uint32_t addr;

    int count = 0;

    for (addr = first_ip; addr < last_ip; addr++) {
        h = new_host(addr);
        push_host(hosts, h);
    }

    h = new_host(addr);
    push_host(hosts, h);

    count += 1;

    return hosts;
}
