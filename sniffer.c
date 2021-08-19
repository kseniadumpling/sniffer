#include "sniffer.h"

// https://www.binarytides.com/packet-sniffer-code-in-c-using-linux-sockets-bsd-part-2/

void print_ip_header(unsigned char* buf, int size) {
    struct iphdr *iph = (struct iphdr *)buf;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    /*char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];

    inet_ntop(source.sin_family, &source.sin_addr, src_str, sizeof src_str);
    inet_ntop(dest.sin_family, &dest.sin_addr, dst_str, sizeof dst_str);*/

    fprintf(logfile, "\nIP header: ");
    // TODO: parse flags and proto, fix conversion
    fprintf(logfile, "v%d, ihl %d, tos %4d, length %5d, id %5d, flags <tbd> " \
        "ttl %4d, proto %d, cksum %d\n", (unsigned int)iph->version, 
        ((unsigned int)(iph->ihl))*4, (unsigned int)iph->tos,
        ntohs(iph->tot_len), ntohs(iph->id), (unsigned int)iph->ttl, 
        (unsigned int)iph->protocol, ntohs(iph->check));
    fprintf(logfile, "src: %s, dst: %s\n", 
        inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
}

void process_packet(unsigned char* buf, int size) {
    struct iphdr *iph = (struct iphdr*)buf;

    switch (iph->protocol) {
        /* TODO:
        case 1:
            print_icmp_packet(buf, size);
            break;
        
        case 6:
            print_tcp_packet(buf, size);
            break;
        
        case 17:
            print_udp_packet(buf, size);
            break;
        */

        default:
            print_ip_header(buf, size);
            break;
    }
}

int main() {
    int saddr_size, data_size;
    struct sockaddr saddr;

    unsigned char *buf = (unsigned char *)malloc(IP_MAXPACKET);

    logfile = fopen("sniff.log", "w");
    if (logfile == NULL) {
        printf("Failed to create a file\n");
        return -2;
    }

    printf("Running...\n");

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("socket err");
        return -1;
    }

    while (1) {
        saddr_size = sizeof saddr;
        data_size = recvfrom(sockfd, buf, IP_MAXPACKET, 0, &saddr, 
            (socklen_t*)&saddr_size);

        if (data_size < 0) {
            printf("recvfrom err: failed to get packet\n");
            return -1;
        }

        process_packet(buf, data_size);
    }
    
    close(sockfd);
    fclose(logfile);
    printf("Finished.\n");

    return 0;
}
