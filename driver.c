#include "rudscan.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage: %s <cidr>\n", argv[0]);
        exit(1);
    }

    int rv;
    char addr_buf[INET_ADDRSTRLEN];

    Hosts hosts = new_hosts(32);

    if (hosts_from_cidr(argv[1], &hosts) == NULL) {
        fprintf(stderr, "unrecoverable error occured\n");
        exit(1);
    }

    rv = mark_active_hosts(&hosts);

    if (rv == -1) {
        fprintf(stderr, "unrecoverable error occured\n");
        exit(1);
    }

    printf("ping scan complete. performing port scan...\n");
    
    for (int i = 0; i < hosts.size; i++) {
        Host h; 
        h = hosts.list[i];
        printf("h.online = %d\n", h.online);
        if (h.online) {
            inet_ntop(AF_INET, &((struct sockaddr_in*)&h.addr)->sin_addr, addr_buf, INET_ADDRSTRLEN);
            printf("Host: %s", addr_buf);
            printf("host is online. performing tcp scan...\n");
            tcp_scan(&hosts.list[i]);
            for (int p = 0; p < h.ports.size; p++) {
                printf("active: %d\n", h.ports.list[p]);
            }
            printf("tcp scan done. performing udp scan ...\n");
            udp_scan(&hosts.list[i]);
            for (int p = 0; p < h.ports.size; p++) {
                printf("active: %d\n", h.ports.list[p]);
            }
            printf("udp scan done.\n");
        }
    }

    return 0;
}
