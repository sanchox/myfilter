#include <stdio.h>      // For standard things
#include <stdlib.h>     // malloc
#include <string.h>     // memset
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/udp.h>     // Provides declarations for udp header
#include <netinet/ip.h>      // Provides declarations for ip header
#include <errno.h>

void process_packet(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_udp_packet(unsigned char * , int);
void print_data (unsigned char* , int);

FILE *logfile;

typedef struct {
    uint64_t tcp;
    uint64_t udp;
    uint64_t icmp;
    uint64_t others;
    uint64_t igmp;
    uint64_t total;
} statistics_t;

statistics_t statistics = {0};

#define BUFFER_SIZE 65536

int main()
{
    logfile = fopen("log.txt","w");
    if (logfile == NULL)
        printf("Unable to create file.");

    printf("Starting...\n");

    uint8_t *buffer = (uint8_t *)malloc(BUFFER_SIZE);

    int socket_raw = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (socket_raw < 0)
    {
        perror("socket() error");
        return(1);
    }
    else
        printf("socket() - Using SOCK_RAW socket and UDP protocol is OK.\n");

    //struct in_addr in;
    struct sockaddr saddr;
    unsigned int saddr_size, data_size;
    while (1)
    {
        saddr_size = sizeof(saddr);
        // Receive a packet
        data_size = recvfrom(socket_raw, buffer, BUFFER_SIZE, 0, &saddr, &saddr_size);
        if (data_size < 0)
        {
            perror("Recvfrom error , failed to get packets\n");
            return(2);
        }
        // Now process the packet
        // process_packet(buffer , data_size);
    }

    close(socket_raw);
    printf("Finished");

    return(0);
}

void process_packet(unsigned char * buffer, int size) {
    // Get the IP Header part of this packet
    struct iphdr * iph = (struct iphdr * ) buffer;
    ++statistics.total;
    switch (iph -> protocol) // Check the Protocol and do accordingly...
    {
    case 1: // ICMP Protocol
        ++statistics.icmp;
        // PrintIcmpPacket(buffer,size);
        break;

    case 2: // IGMP Protocol
        ++statistics.igmp;
        break;

    case 6: // TCP Protocol
        ++statistics.tcp;
        break;

    case 17: // UDP Protocol
        ++statistics.udp;
        print_udp_packet(buffer, size);
        break;

    default: // Some Other Protocol like ARP etc.
        ++statistics.others;
        break;
    }
    printf("TCP : %lud   UDP : %lud   ICMP : %lud   IGMP : %lud   Others : %lud   Total : %lud\r",
           statistics.tcp, statistics.udp, statistics.icmp, statistics.igmp, statistics.others, statistics.total);
}

void print_ip_header(unsigned char * buffer, int size) {
    struct sockaddr_in source, dest;

    //unsigned short iphdrlen;

    struct iphdr * iph = (struct iphdr * ) buffer;
    //iphdrlen = iph->ihl*4;

    memset( & source, 0, sizeof(source));
    source.sin_addr.s_addr = iph -> saddr;

    memset( & dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph -> daddr;

    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    fprintf(logfile, "   |-IP Version        : %d\n",
            (unsigned int) iph -> version);
    fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",
            (unsigned int) iph -> ihl, ((unsigned int)(iph -> ihl)) * 4);
    fprintf(logfile, "   |-Type Of Service   : %d\n",
            (unsigned int) iph -> tos);
    fprintf(logfile, "   |-IP Total Length   : %d  Bytes(size of Packet)\n",
            ntohs(iph -> tot_len));
    fprintf(logfile, "   |-Identification    : %d\n", ntohs(iph -> id));
    //fprintf(logfile,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile, "   |-TTL      : %d\n", (unsigned int) iph -> ttl);
    fprintf(logfile, "   |-Protocol : %d\n", (unsigned int) iph -> protocol);
    fprintf(logfile, "   |-Checksum : %d\n", ntohs(iph -> check));
    fprintf(logfile, "   |-Source IP        : %s\n",
            inet_ntoa(source.sin_addr));
    fprintf(logfile, "   |-Destination IP   : %s\n",
            inet_ntoa(dest.sin_addr));
}

void print_udp_packet(unsigned char * buffer, int size) {

    unsigned short iphdrlen;

    struct iphdr * iph = (struct iphdr * ) buffer;
    iphdrlen = iph -> ihl * 4;

    struct udphdr * udph = (struct udphdr * )(buffer + iphdrlen);

    fprintf(logfile,
            "\n\n***********************UDP Packet*************************\n");

    print_ip_header(buffer, size);

    fprintf(logfile, "\nUDP Header\n");
    fprintf(logfile, "   |-Source Port      : %d\n", ntohs(udph -> source));
    fprintf(logfile, "   |-Destination Port : %d\n", ntohs(udph -> dest));
    fprintf(logfile, "   |-UDP Length       : %d\n", ntohs(udph -> len));
    fprintf(logfile, "   |-UDP Checksum     : %d\n", ntohs(udph -> check));

    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    print_data(buffer, iphdrlen);

    fprintf(logfile, "UDP Header\n");
    print_data(buffer + iphdrlen, sizeof udph);

    fprintf(logfile, "Data Payload\n");
    print_data(buffer + iphdrlen + sizeof udph,
               (size - sizeof udph - iph -> ihl * 4));

    fprintf(logfile,
            "\n###########################################################");
}

void print_data(unsigned char * data, int size) {
    int i,j;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0) // if one line of hex printing is
            // complete...
        {
            fprintf(logfile, "         ");
            for (j = i - 16; j < i; j++) {
                if (data[j] >= 32 && data[j] <= 128)
                    fprintf(logfile, "%c", (unsigned char) data[j]); // if
                // its
                // a
                // number
                // or
                // alphabet

                else
                    fprintf(logfile, "."); // otherwise print a dot
            }
            fprintf(logfile, "\n");
        }

        if (i % 16 == 0)
            fprintf(logfile, "   ");
        fprintf(logfile, " %02X", (unsigned int) data[i]);

        if (i == size - 1) // print the last spaces
        {
            for (j = 0; j < 15 - i % 16; j++)
                fprintf(logfile, "   "); // extra spaces

            fprintf(logfile, "         ");

            for (j = i - i % 16; j <= i; j++) {
                if (data[j] >= 32 && data[j] <= 128)
                    fprintf(logfile, "%c",
                            (unsigned char) data[j]);
                else
                    fprintf(logfile, ".");
            }
            fprintf(logfile, "\n");
        }
    }
}
