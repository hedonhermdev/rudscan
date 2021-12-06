#include "rudscan.h"

int tcp_scan(Host *h)
{
    int *active_ports = calloc(32, sizeof(int));
    int size_active_ports = 32;
    int active_ports_idx = 0;

    struct sockaddr_in sockaddr;
    bzero((void *)&sockaddr, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr = ((struct sockaddr_in*) h->addr)->sin_addr;

    fd_set fdset;

    struct timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;

    int ret, so_error;
    unsigned int len = sizeof(so_error);

    for (int port = 1; port < PORT_MAX; port++)
    {
        sockaddr.sin_port = htons(port);
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        fcntl(sockfd, F_SETFL, O_NONBLOCK);
        FD_ZERO(&fdset);
        FD_SET(sockfd, &fdset);
        ret = connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));

        if (ret < 0 && errno != EINPROGRESS)
        {
            close(sockfd);
            continue;
        }
        if (ret == 0)
        {
            printf("active: %d\n", port); 
            push_port(&h->ports, port);
        }
        else if (select(sockfd + 1, NULL, &fdset, NULL, &tv) == 1)
        {
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0)
            {
                printf("active: %d\n", port); 
                push_port(&h->ports, port);
            }
        }
        close(sockfd);
    }
    return 0;
}

void wait_rtt(struct sockaddr_in servaddr, int num_rtt)
{
    fd_set fdset;

    struct timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;

    int ret, so_error;
    unsigned int len = sizeof(so_error);
    for (int i = 0; i < num_rtt; i++)
    {
        servaddr.sin_port = htons(INACTIVE_PORT);

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        fcntl(sockfd, F_SETFL, O_NONBLOCK);
        FD_ZERO(&fdset);
        FD_SET(sockfd, &fdset);
        ret = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
        if (ret < 0 && errno != EINPROGRESS)
        {
            close(sockfd);
            continue;
        }
        if (ret == 0)
        {
            continue;
        }
        select(sockfd + 1, NULL, &fdset, NULL, &tv);
        close(sockfd);
    }
}

void readICMP(int rawfd, Host* h, struct sockaddr_in servaddr, int port_start, int port_end)
{

    int hlen1, hlen2, icmplen, ret;
    unsigned int len;
    int n;
    struct ip *ip, *hip;
    struct icmp *icmp;
    struct udphdr *udp;
    int inactive_ports[BATCHSIZE_UDP_PORT];
    for (int i = 0; i < BATCHSIZE_UDP_PORT; i++)
    {
        inactive_ports[i] = -1;
    }
    if (port_start == 0)
    {
        inactive_ports[0] = 1;
    }

    char *recvbuf = (char *)malloc(DGRAM_SIZE);
    struct sockaddr_in recvsa;
    len = sizeof(recvsa);
    //wait for 2 RTT using TCP connect. This ensures that we have recieved all ICMP messages sent by the remote host
    wait_rtt(servaddr, 2);
    while ((n = recvfrom(rawfd, recvbuf, DGRAM_SIZE, MSG_DONTWAIT, (struct sockaddr *)&recvsa, &len)) > 0)
    {
        ip = (struct ip *)recvbuf;
        hlen1 = ip->ip_hl << 2;
        if (ip->ip_src.s_addr != servaddr.sin_addr.s_addr)
        {
            continue;
        }
        icmp = (struct icmp *)(recvbuf + hlen1);
        icmplen = n - hlen1;
        if (icmplen < 8)
        {
            continue;
        }

        sleep(1);
        if (icmp->icmp_type == ICMP_UNREACH && icmp->icmp_code == ICMP_UNREACH_PORT)
        {
            if (icmplen < 8 + sizeof(struct ip))
                continue;
            hip = (struct ip *)(recvbuf + hlen1 + 8);
            hlen2 = hip->ip_hl << 2;
            if (icmplen < 8 + hlen2 + 4)
                continue;
            udp = (struct udphdr *)(recvbuf + hlen1 + 8 + hlen2);
            int set_port_false = ntohs(udp->uh_dport);
            if (set_port_false >= port_start && set_port_false <= port_end)
            {
                inactive_ports[set_port_false - port_start] = 1;
            }
        }
    }
    for (int i = 0; i < BATCHSIZE_UDP_PORT; i++)
    {
        if (inactive_ports[i] == -1)
        {
            push_port(&h->ports, port_start+i);
        }
    }
}

int udp_scan(Host *h) {
    int *active_ports = calloc(32, sizeof(int));
    int size_active_ports = 32;
    int active_ports_idx = 0;

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_addr = ((struct sockaddr_in*)h->addr)->sin_addr;
    servaddr.sin_family = AF_INET;

    char *senddata = "101010";

    int rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    setuid(getuid());

    for (int port = 1; port < PORT_MAX; port++)
    {
        if (port % BATCHSIZE_UDP_PORT == 0 && port != 0)
        {
            readICMP(rawfd, h, servaddr, port - BATCHSIZE_UDP_PORT, port - 1);
        }
        servaddr.sin_port = htons(port);
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        int bytes_sent;
        for (int try = 0; try < TRIES; try++)
        {
            bytes_sent = sendto(sockfd, senddata, 5, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
            if (bytes_sent < 0)
            {
                perror("sendto");
            }
        }
        close(sockfd);
    }

    close(rawfd);

    return 0;
}
