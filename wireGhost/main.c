#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "arraylist.h"
#include "string.h"


#define SIZE_ETHERNET 14
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

Array ack_table;
Array seq_table;
struct arraylist source;
struct arraylist destination;

struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

u_char* handle_IP
(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
 packet);
/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};


pcap_t* descr;






uint16_t ip_checksum(unsigned char* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    unsigned char* data=(unsigned char*)vdata;
    
    // Initialise the accumulator.
    uint64_t acc=0xffff;
    
    // Handle any partial block at the start of the data.
    unsigned int offset=((uintptr_t)data)&3;
    if (offset) {
        size_t count=4-offset;
        if (count>length) count=length;
        uint32_t word=0;
        memcpy(offset+(char*)&word,data,count);
        acc+=ntohl(word);
        data+=count;
        length-=count;
    }
    
    // Handle any complete 32-bit blocks.
    char* data_end=data+(length&~3);
    while (data!=data_end) {
        uint32_t word;
        memcpy(&word,data,4);
        acc+=ntohl(word);
        data+=4;
    }
    length&=3;
    
    // Handle any partial block at the end of the data.
    if (length) {
        uint32_t word=0;
        memcpy(&word,data,length);
        acc+=ntohl(word);
    }
    
    // Handle deferred carries.
    acc=(acc&0xffffffff)+(acc>>32);
    while (acc>>16) {
        acc=(acc&0xffff)+(acc>>16);
    }
    
    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset&1) {
        acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
    }
    
    // Return the checksum in network byte order.
    return htons(~acc);
}





/* Callback function which modifies the pacet */
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */
    
    int size_ip;
    int size_tcp;
    int size_payload;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    
    /* define/compute tcp payload (segment) offset */
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    
    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    
    //Inserted code ends
    struct ether_header * eptr = (struct ether_header *) packet;
    u_int16_t type = ntohs(eptr->ether_type);
    
    if(type == ETHERTYPE_IP) {/* handle IP packet */
        
        u_char* modifiedPacket = (u_char*) malloc((2 * *(packet + 17) + 14) * sizeof(u_char));
        memcpy(modifiedPacket, packet, (*(packet + 17) + 14));
        
        /*
        int j = *(packet + 17) + 14;
        for(; j < 2 * *(packet + 17) + 14; j++){//Increase the size of the payload
            modifiedPacket[j] = 0;
        }
        */
        
        
        unsigned char* IP = (char*) malloc(sizeof(char) * 20);
        for(int j = 14; j < 20 + 14; j++){
            IP[j - 14] = modifiedPacket[j];
        }
        IP[3] = 2 * IP[3];
        *(modifiedPacket + 3 + 14) = IP[3];
        *(IP + 10) = 0x00;
        *(IP + 11) = 0x00;
        short checksum = ip_checksum(IP, 20);
        *(modifiedPacket + 10 + 14) = checksum & 0xff;
        *(modifiedPacket + 11 + 14) = ((checksum >> 8) & 0xff);
        int packetsize = (modifiedPacket[3 + 14] ) + 14;
        if(pcap_sendpacket(descr, modifiedPacket, packetsize) < 0){//to send the packet, you must specify the interface, the packet, and the size of the packet
            printf("packet not successfully send");
        }
    }
    else{
        if(pcap_sendpacket(descr, packet, pkthdr->len) < 0){
            printf("packet not successfully sent");
        }
    }
}
//returns index if pair is in ack table and -1 if value is not
int in_ack_table(char * searchsource, char * searchdest){
    Array appinsrc;
    initArray(&appinsrc, 0);
    Array appindest;
    initArray(&appindest,0);
    int i = 0;
    for(;i<arraylist_get_size(source);i++){
        if(strcmp(source.data[i], searchsource) == 0) {
            insertArray(&appinsrc,i);
        }
        if(strcmp(destination.data[i], searchdest) == 0) {
            insertArray(&appindest,i);
        }
    }
    int j = 0;
    for(;j<size(&appinsrc);j++){
        if (contains(&appindest, getArray(&appinsrc,j))==1){
            return j;
        }
    }
    return -1;
}




/* handle ethernet packets, much of this code gleaned from
 * print-ether.c from tcpdump source
 */
int main(int argc,char **argv)
{
    arraylist_initial(&source);
    arraylist_initial(&destination);
    initArray((&ack_table), 0);
    initArray(&seq_table, 0);


    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    struct bpf_program fp;      /* hold compiled filter expression     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    u_char* args = NULL;
    
    char* find = argv[2];
    char* replace = argv[3];
    int difference = strlen(find)-strlen(replace);
    
    /* Options must be passed in as a string because I am lazy */
    if(argc < 4){
        fprintf(stdout,"Usage: %s numpackets \"options\"\n",argv[0]);
        return 0;
    }
    
    /* device to listen*/
    dev = pcap_lookupdev(errbuf);
    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev,&netp,&maskp,errbuf);
    
    /* open device for reading. NOTE: defaulting to
     * promiscuous mode*/
    descr = pcap_open_live(dev,100000,1,-1,errbuf); //max packet size capture will be 2048
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }
    
    
    if(argc > 2)
    {
        /* Lets try and compile the program.. non-optimized */
        if(pcap_compile(descr,&fp,argv[2],0,netp) == -1)
        { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }
        
        /* set the compiled program as the filter */
        if(pcap_setfilter(descr,&fp) == -1)
        { fprintf(stderr,"Error setting filter\n"); exit(1); }
    }
    
    /* ... and loop */
    pcap_loop(descr,atoi(argv[1]),my_callback,args);
    
    pcap_freecode(&fp);
    pcap_close(descr);
    
    fprintf(stdout,"\nfinished\n");
    return 0;
}
