#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<net/ip.h>
#include<net/tcp.h>
#include<linux/hashtable.h>
#include "arraylist.h"
//static Array ack_table; //This is the table that will store the acknoledgment numbers
//static Array seq_table; //This is the table that will store sequence numbers
//struct arraylist source; //These are to be used in conjunction with the above
//struct arraylist destination;
//
////returns index if pair is in ack table and -1 if value is not
//int in_ack_table(u32 searchsource, u32 searchdest){
//    Array appinsrc;
//    Array appindest;
//    int i;
//    int j;
//
//    initArray(&appinsrc, 2);
//    initArray(&appindest,2);
//
//    for(i =0;i<arraylist_get_size(source);i++){
//        if(source.data[i]==searchsource){
//            insertArray(&appinsrc,i);
//        }
//        if(destination.data[i]==searchdest){
//            insertArray(&appindest,i);
//        }
//    }
//    for(j = 0;j<size(&appinsrc);j++){
//        if (contains(&appindest, getArray(&appinsrc,j))==1){
//            return j;
//        }
//    }
//    return -1;
//}
//
//void add_table_element(u32 src, u32 dst){
//    arraylist_add(&source, src);
//    arraylist_add(&destination, dst);
//    insertArray(&seq_table, 0);
//    insertArray(&ack_table, 0);
//}
//
//void add_table_offset(int index, int offset){
//    int oldvalue;
//    int oldvalue1;
//    oldvalue=getArray(&ack_table, offset);
//    updateArray(&ack_table, index, (oldvalue-offset));
//    oldvalue1=getArray(&seq_table, offset);
//    updateArray(&seq_table, index, (oldvalue1+offset));
//}
//
//
//void update_keys(u32 sourcekey, u32 destkey){
//    if (in_ack_table(sourcekey, destkey)==(-1)){
//        add_table_element(sourcekey, destkey);
//    }
//    if (in_ack_table(destkey, sourcekey)==(-1)){
//        add_table_element(destkey, sourcekey);
//    }
//    
//}
//
//
// Parameters to be passed to the module
static char * keyToReplace;
static char * replacementForKey;

// Paramter declarations 
module_param(keyToReplace, charp, 0);
module_param(replacementForKey, charp, 0);

static inline int ipToInt(int a, int b, int c, int d) {
	return (a * 16777216) + (b * 65536) + (c * 256) + d;
}

struct temp {
	int ip;
	int offset;
};

struct temp seqTab[5];
struct temp ackTab[5];

void storeVal(char * table, struct temp t) {
	int i;
	if (!strcmp(table, "seqTab")) {
		for (i = 0; i < 5; i++) {
			if (!seqTab[i].ip) {
				seqTab[i] = t;
			}
		}
	}
	else {
		for (i = 0; i < 5; i++) {
			if (!ackTab[i].ip) {
				ackTab[i] = t;
			}
		}
	}	
}

void addVal(char * table, struct temp t) {
	int i;
	if (!strcmp(table, "seqTab")) {
		for (i = 0; i < 5; i++) {
			if (seqTab[i].ip == t.ip) {
				seqTab[i].offset = t.offset;
			}
		}
	}
	else {
		for (i = 0; i < 5; i++) {
			if (ackTab[i].ip == t.ip) {
				ackTab[i].offset = t.offset;
			}
		}
	}
}

int getVal(char * table, int ip) {
	int i;
	if (!strcmp(table, "seqTab")) {
		for (i = 0; i < 5; i++) {
			if (seqTab[i].ip == ip) {
				return seqTab[i].offset;
			}
		}
	}
	else {
		for (i = 0; i < 5; i++) {
			if (ackTab[i].ip == ip) {
				return ackTab[i].offset;
			}
		}
	}
	return -1;
}


		

int payloadFind(char* payload, const char* key, const char* replacement) {
        char * lastOccurence;
        char * nextOccurence;
        char * temp;
        int seen;
        temp = kmalloc(1500, GFP_KERNEL);
        seen = 0;
        nextOccurence = strstr(payload, key);
        lastOccurence = (char *)payload;
        while (nextOccurence != NULL) {
                seen++;
//              temp = realloc(temp, strlen(payload)-seen*(strlen(key)+strlen(replacement)));
                strncat(temp, lastOccurence, nextOccurence-lastOccurence);
                strcat(temp, replacement);
                lastOccurence = nextOccurence+strlen(key);
                nextOccurence = strstr(nextOccurence+1, key);
        }
//      temp = realloc(temp, (strlen(payload)-seen*(strlen(key)+strlen(replacement))+strlen(lastOccurence)));
        strcat(temp, lastOccurence);
	strncpy(payload, temp, strlen(temp));
	payload[strlen(temp)] = '\0';
	return seen;
}

static struct nf_hook_ops netfilter_ops_in; //NF_INET_PRE_ROUTING
static struct nf_hook_ops netfilter_ops_out; //NF_INET_POST_ROUTING
//Modify this function how you please to change what happens to incoming packets
unsigned int in_hook(void *priv, struct sk_buff * skb, const struct nf_hook_state *state) {
	//Couple lines need to be pasted
	struct tcphdr *tcph = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct temp t;
	unsigned char *tail, *user_data, *it;
	char *payload;
	int lenOrig, tcp_len, replacements, offset;
	__u16 sport, dport, ip_len;
	__u32 saddr, daddr;
	uint32_t seq, ack;
	seq = ack = 0;
	payload = kmalloc(1500, GFP_KERNEL);

	/* Ignore the skb if it is empty */
	if (!skb)
		return NF_ACCEPT;

	/* Convert the source IP address (saddr), source port (sport), 
	   destination IP address (daddr), and destination port (dport)
	   from the network format to the host format */
	saddr = ntohl(iph->saddr);
	daddr = ntohl(iph->daddr);
	sport = ntohs(tcph->source);
	dport = ntohs(tcph->dest);

	/* User_data points to the beginning of the payload in the skb
	   tail points to the end of the payload in skb */
	tail = skb_tail_pointer(skb);
	user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));

	/* Filter all IP's except those we are interested in */
	if(saddr == ipToInt(10,0,2,12) || saddr == ipToInt(10,0,2,13)) {
		//skb_unshare(skb, GFP_ATOMIC); //Must unshare the skb to modify it

		/* Loops through the skb payload and stores it in char * payload */
		lenOrig = 0;
		for (it = user_data; it != tail; ++it) {
			char c = *(char *)it;
			payload[lenOrig] = c;
			lenOrig++;
		}
		payload[lenOrig] = '\0';

		//printk("NETFILTER.C: DATA OF ORIGINAL SKB: %s\n", payload);

		/* Change the payload data stored in char * payload */
		replacements = payloadFind(payload, "a", "xyz");

		if (getVal("seqTab", saddr) == -1) {
			t.ip = saddr;
			t.offset = 0;
			storeVal("seqTab", t);
			storeVal("ackTab", t);
		}
		if (getVal("ackTab", daddr) == -1) {
			t.ip = daddr;
			t.offset = 0;
			storeVal("ackTab", t);
			storeVal("seqTab", t);
		}


		/* Change sequence number from network to host, add offset, back to network */
		seq = ntohl(tcph->seq);
		seq += getVal("seqTab", saddr);
		tcph->seq = htonl(seq);
		
		/* Change acknowledgement number from network to host, add offset, back to network */
		ack = ntohl(tcph->ack_seq);
		ack += getVal("ackTab", saddr);
		tcph->ack_seq = htonl(ack);

		printk("NETFILTER.C: Seqoff: %d, Ackoff: %d\n", getVal("seqTab", saddr), getVal("ackTab", saddr));

		if (strlen(payload)-lenOrig) {
			offset = strlen(payload)-lenOrig;
			t.ip = saddr;
			t.offset = getVal("seqTab", saddr) + offset;
			addVal("seqTab", t);
			t.ip = daddr;
			t.offset = getVal("ackTab", daddr) - offset;
			addVal("ackTab", t);
		}

		/* Change the size of the skb so that it allows for larger payloads
		   may fail if the changed payload is shorter */
		if(pskb_expand_head(skb, 0, strlen(payload)-skb_tailroom(skb), GFP_ATOMIC)) {
			//printk("Sorry, we couldn't expand the skb, you'll just have to accept it\n");
			return NF_ACCEPT;
		}

		/* Refresh header pointers after skb expand */
		tcph = tcp_hdr(skb);
		iph = ip_hdr(skb);

		/* Reserve space in the skb for the data */
		skb_put(skb, strlen(payload)-lenOrig);

		/* memcpy into user_data the modified payload */
		user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
		memcpy(user_data, payload, strlen(payload));

		/* Convert the ip length from the network, change it to the new length, back to network */
		ip_len = ntohs(iph->tot_len);
		ip_len += strlen(payload)-lenOrig;
		iph->tot_len = htons(ip_len);

		/* Update TCP and IP checksums */
		tcp_len = skb->len - 4 * iph->ihl;
		iph->ttl += 1;
		ip_send_check(iph);
		tcph->check = 0;
		tcph->check = tcp_v4_check(tcp_len, iph->saddr, iph->daddr, csum_partial((char *)tcph, tcp_len, 0));

	}
	return NF_ACCEPT;
}
//Modify this function how you please to change what happens to outgoing packets
unsigned int out_hook(void *priv, struct sk_buff * skb, const struct nf_hook_state *state) {
	struct tcphdr * tcph = tcp_hdr(skb);
	struct iphdr * iph = ip_hdr(skb);
	unsigned char *user_data, *it, *tail;
	u32 saddr;

	/* Convert source IP address from network format to host format */
	saddr = ntohl(iph->saddr);

	/* Same as above, user_data points to beginning of payload and tail 
	   points to the end of the payload */
	user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
	tail = skb_tail_pointer(skb);

	/* Filter for only the IP addresses we are interested in */
	if(saddr == ipToInt(10,0,2,12) || saddr == ipToInt(10,0,2,13)) {
		/* Loop through the skb payload and print it */
		//printk("NETFILTER.C: OUTGOING PACKET DATA: ");
		for (it = user_data; it != tail; ++it) {
			char c = *(char *)it;
			if (c == '\0') {
				break;
			}
			//printk("%c", c);
		}
		//printk("\n");

	}
	return NF_ACCEPT; //Let packets go through
}

int init_module() {
//	arraylist_initial(&source);
//	arraylist_initial(&destination);
//	initArray((&ack_table), 2);
//	initArray(&seq_table, 2);

	netfilter_ops_in.hook = in_hook;
	netfilter_ops_in.pf = PF_INET;
	netfilter_ops_in.hooknum = NF_INET_PRE_ROUTING;
	netfilter_ops_in.priority = NF_IP_PRI_FIRST;

	netfilter_ops_out.hook = out_hook;
	netfilter_ops_out.pf = PF_INET;
	netfilter_ops_out.hooknum = NF_INET_POST_ROUTING;
	netfilter_ops_out.priority = NF_IP_PRI_FIRST;


	nf_register_hook(&netfilter_ops_in);
	nf_register_hook(&netfilter_ops_out);
	//Add array initializers	
	return 0;
}
void cleanup_module() {
	nf_unregister_hook(&netfilter_ops_in);
	nf_unregister_hook(&netfilter_ops_out);
}
