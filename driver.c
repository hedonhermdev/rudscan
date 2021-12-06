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
        inet_ntop(AF_INET, &(h.addr->sa_data[2]), addr_buf, INET_ADDRSTRLEN);
        printf("Host: %s\n", addr_buf);
        
        if (h.online) {
            printf("host is online. performing tcp scan...\n");
            /* tcp_scan(&hosts.list[i]); */
            /* for (int p = 0; p < h.ports.size; p++) { */
            /*     printf("active: %d\n", h.ports.list[p]); */
            /* } */
            printf("tcp scan done. performing udp scan ...\n");
            udp_scan(&hosts.list[i]);
            for (int p = 0; p < h.ports.size; p++) {
                printf("active: %d\n", h.ports.list[p]);
            }
            printf("udp scan done.\n");
        } else {
            printf("host is offline. skipping port scan...\n");
        }
    }

    return 0;
}
