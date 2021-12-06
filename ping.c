#include "rudscan.h"

int getrawsocket() {
    int sockfd;
    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    setuid(getuid());

    struct timeval timeout;      
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    
    if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0)
        perror("setsockopt");

    return sockfd;
}

uint16_t in_cksum(uint16_t *addr, size_t len) {
	int				nleft = len;
	uint32_t		sum = 0;
	uint16_t		*w = addr;
	uint16_t		answer = 0;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w ;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);	
	sum += (sum >> 16);			
    
	answer = ~sum;

	return answer;
}

void makeicmppacket(struct icmp* buf) {
    buf->icmp_type = ICMP_ECHO;
    buf->icmp_code = 0;
    buf->icmp_id = getpid();
    buf->icmp_seq = 0;
    memset(buf->icmp_data, 0xa5, 56);
    buf->icmp_cksum = 0;

    buf->icmp_cksum = in_cksum((uint16_t*)buf, 64);
}

int checkhost(int sockfd, char* sendbuf, char* recvbuf, struct sockaddr* host) {
    int rv;
    struct icmp* resp;

    makeicmppacket((struct icmp*)sendbuf);

       


    
    // skipping the first 20 bytes because that is the IP header

    return resp->icmp_type;
}

int mark_active_hosts(Hosts* hosts) {
    int rv;
    char sendbuf[1024];
    char recvbuf[1024];
    int sockfd;

    if ((sockfd = getrawsocket()) < 0) {
        return -1;
    }

    makeicmppacket((struct icmp*) sendbuf);

    for (int i = 0; i < hosts->size; i++) {
        Host* h = &hosts->list[i];

        socklen_t addrlen = (socklen_t) sizeof(h->addr);

        if ((rv = sendto(sockfd, sendbuf, 64, 0, h->addr, addrlen)) < 0) {
            perror("sendto");
            continue;
        }

    }

    struct icmp* resp;

    for (int i = 0; i < hosts->size; i++) {
        Host* h = &hosts->list[i];

        socklen_t addrlen = (socklen_t) sizeof(h->addr);

        if ((rv = recvfrom(sockfd, recvbuf, 1024, 0, h->addr, &addrlen)) < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            perror("recvfrom");
            continue;
        }

        resp = (struct icmp*)(&recvbuf[20]);

        int icmp_type = resp->icmp_type;

        h->online = icmp_type == 0 ? true : false;
    }

    return 0;
}
