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

Array ack_table; //This is the table that will store the acknoledgment numbers
Array seq_table; //This is the table that will store sequence numbers
struct arraylist source; //These are to be used in conjunction with the above
struct arraylist destination;
char errbuf[PCAP_ERRBUF_SIZE];


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
int offset;
char * replace;
char * find;


int count = 0;

void payloadFind(const char* payload, const char* key, const char* replacement) {
	if (payload == NULL) {
		return;
	}
    char * lastOccurence = (char *)payload;
    char * nextOccurence = strstr(payload, key);
    char temp[3000];
    int seen = 0;
    while (nextOccurence != NULL) {
        seen++;
        count++;
        //		temp = realloc(temp, strlen(payload)-seen*(strlen(key)+strlen(replacement)));
        strncat(temp, lastOccurence, nextOccurence-lastOccurence);
        strcat(temp, replacement);
        lastOccurence = nextOccurence+strlen(key);
        nextOccurence = strstr(nextOccurence+1, key);
    }
    //	temp = realloc(temp, (strlen(payload)-seen*(strlen(key)+strlen(replacement))+strlen(lastOccurence)));
    strcat(temp, lastOccurence);
    payload = temp;
}


uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;
    
    // Initialise the accumulator.
    uint32_t acc=0xffff;
    
    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }
    
    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }
    
    // Return the checksum in network byte order.
    return htons(~acc);
}





//returns index if pair is in ack table and -1 if value is not
int in_ack_table(char * searchsource, char * searchdest){
    Array appinsrc;
    initArray(&appinsrc, 2);
    Array appindest;
    initArray(&appindest,2);
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

void add_table_element(char * src, char * dst){
    arraylist_add(&source, src);
    arraylist_add(&destination, dst);
    insertArray(&seq_table, 0);
    insertArray(&ack_table, 0);
}

void add_table_offset(int index, int offset){
    int oldvalue=getArray(&ack_table, offset);
    updateArray(&ack_table, index, (oldvalue-offset));
    int oldvalue1=getArray(&seq_table, offset);
    updateArray(&seq_table, index, (oldvalue1+offset));
}


char * computeSourceKey(const u_char * packet){
    
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */

    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    return inet_ntoa(ip->ip_src);
}


char * computeDestKey(const u_char * packet){
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    return inet_ntoa(ip->ip_dst);
}


void update_keys(char * sourcekey, char * destkey){
    if (in_ack_table(sourcekey, destkey)==(-1)){
        add_table_element(sourcekey, destkey);
    }
    if (in_ack_table(destkey, sourcekey)==(-1)){
        add_table_element(destkey, sourcekey);
    }
    
}
/* Callback function which modifies the pacet */
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    printf("entered callback\n");
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */
    const struct sniff_ethernet *ethernet2;  /* The ethernet header [1] */
    const struct sniff_ip *ip2;              /* The IP header */
    const struct sniff_tcp *tcp2;            /* The TCP header */
    const char *payload2;                    /* Packet payload */
    
    int size_ip;
    int size_tcp;
    int size_payload;
    
    int size_ip2;
    int size_tcp2;
    int size_payload2;
    
    struct ether_header * eptr = (struct ether_header *) packet;
    u_int16_t type = ntohs(eptr->ether_type);
    
    if(type == ETHERTYPE_IP) {/* handle IP packet */
        printf("entered ethernet\n");
        /* define ethernet header */
        ethernet = (struct sniff_ethernet*)(packet);
        
        /* define/compute ip header offset */
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        
        size_ip = IP_HL(ip)*4;
        int lengthPacket =ip->ip_len;
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
        /*
        u_char* modifiedPacket = (u_char*) malloc((2 * *(packet + 17) + 14) * sizeof(u_char));
        memcpy(modifiedPacket, packet, (*(packet + 17) + 14));
         */
        u_char* modifiedPacket = malloc(lengthPacket*sizeof(u_char));
        memcpy(modifiedPacket, packet, lengthPacket);
        struct ether_header * eptr2 = (struct ether_header *) modifiedPacket;
        ethernet2 = (struct sniff_ethernet*)(modifiedPacket);
        ip2 = (struct sniff_ip*)(modifiedPacket + SIZE_ETHERNET);
        size_ip2 = IP_HL(ip2)*4;
        tcp2 = (struct sniff_tcp*)(modifiedPacket + SIZE_ETHERNET + size_ip2);

        /* define/compute tcp payload (segment) offset */
        payload = (u_char *)(modifiedPacket + SIZE_ETHERNET + size_ip2 + size_tcp2);
        
        char * key1 = computeSourceKey(modifiedPacket);
        char * key2 = computeDestKey(modifiedPacket);
        update_keys(key1, key2);
        update_keys(key2, key1);
        int index = in_ack_table(key1, key2);
        int seqoff = getArray(&seq_table, index);
        int ackoff = getArray(&ack_table, index);

        //copies a packet and modifies the TCP acknowledgement and sequence numbers;
        long newseq=(tcp2->th_seq)+seqoff; //Uses a long since a long is 4 bytes
        long newack=(tcp2->th_ack)+ackoff;
        *(modifiedPacket+SIZE_ETHERNET+size_ip2+4)=newseq;
        *(modifiedPacket+SIZE_ETHERNET+size_ip2+8)=newack;
        printf("A\n");
        //update payload
	printf("Payload: %s", payload);
        payloadFind(payload, find, replace);
        printf("B\n");

        int replacements = count;
        count = 0;
        //update table
        int total_offset = offset * replacements;
        add_table_offset(index, total_offset);
        short newLength=*(modifiedPacket+SIZE_ETHERNET+2)+total_offset;
        *(modifiedPacket+SIZE_ETHERNET+2)=newLength;
        
        
        unsigned char* IP = (char*) malloc(sizeof(char) * 20);
        for(int j = 14; j < 20 + 14; j++){
            IP[j - 14] = modifiedPacket[j];
        }
        IP[3] = 2 * IP[3];
        *(modifiedPacket + 3 + 14) = IP[3];
        *(IP + 10) = 0x00;
        *(IP + 11) = 0x00;
        short checksum = ip_checksum(IP, 20);
        *(modifiedPacket + 10 + SIZE_ETHERNET) = checksum & 0xff;
        *(modifiedPacket + 11 + SIZE_ETHERNET) = ((checksum >> 8) & 0xff);
        int packetsize = *(modifiedPacket+2+ 14) + total_offset;
        if(pcap_sendpacket(descr, modifiedPacket, packetsize) < 0){//to send the packet, you must specify the interface, the packet, and the size of the packet
            pcap_perror(descr,errbuf);
            printf("packet not successfully sent");
        }
    }/*
    else{
        printf("not ethernet");
        if(pcap_sendpacket(descr, packet, pkthdr->len) < 0){
            printf("packet not successfully sent");
        }
    }*/
}


/* handle ethernet packets, much of this code gleaned from
 * print-ether.c from tcpdump source
 */
int main(int argc,char **argv)
{
    arraylist_initial(&source);
    arraylist_initial(&destination);
    initArray((&ack_table), 2);
    initArray(&seq_table, 2);


    char *dev;
    
    struct bpf_program fp;      /* hold compiled filter expression     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    u_char* args = NULL;
    
    find = argv[3];
    replace = argv[4];
    offset = strlen(find)-strlen(replace);
    
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
printf("About to enter callback\n");
    pcap_loop(descr,atoi(argv[1]),my_callback,args);
    
    pcap_freecode(&fp);
    pcap_close(descr);
    
    fprintf(stdout,"\nfinished\n");
    return 0;
}
