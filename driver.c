#include "rudscan.h"

int main(int argc, char** argv) {

    if (argc < 2) {
        printf("usage: %s <cidr>\n", argv[0]);
        exit(1);
    }

    Hosts hosts = new_hosts(32);

    hosts_from_cidr(argv[1], &hosts); 
    printf("size: %lu", hosts.size);

    mark_active_hosts(&hosts);
    
    for (int i = 0; i < hosts.size; i++) {
        Host h; 
        h = hosts.list[i];
        printf("h.online = %d\n", h.online);
        if (h.online) {
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
        }
    }

    return 0;
}
