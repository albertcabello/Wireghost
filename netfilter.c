#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<net/ip.h>
#include<net/tcp.h>
#include "dictionary.h" 

// Parameters to be passed to the module
static char * keyToReplace;
static char * replacementForKey;

// Paramter declarations 
module_param(keyToReplace, charp, 0);
module_param(replacementForKey, charp, 0);

//Sequence and acknowledgement tables
entry* seqTable[HASH_TABLE_SIZE];
entry* ackTable[HASH_TABLE_SIZE];

/* Converts four IP octets to an integer that can be used for comparison */
static inline int ipToInt(int a, int b, int c, int d) {
	/* IP to int is first octet * 256^3 + second octet * 256^2 + third octet * 256 + fourth octet */
	//return (a * 16777216) + (b * 65536) + (c * 256) + d;
	/* Bit shifting is quicker than multiplication
	 * 2^24 = 256^3, 2^16 = 256^2, 256 = 2^8 */
	return (a << 24) + (b << 16) + (c << 8) + d;
}

/* Given payload, replace every occurence of key in payload with replacement, payload modified in place
 * returns the amount of times key was replaced */
int payloadFind(char* payload, const char* key, const char* replacement) {
        char * lastOccurence; //Last occurence of key
        char * nextOccurence; //Next occurence of key
        char * temp; //Temporary array to store the new payload
        int seen; //Amount of times key has been replaced
        temp = kmalloc(1500, GFP_KERNEL);
        seen = 0;
        nextOccurence = strstr(payload, key);
        lastOccurence = (char *)payload;
        while (nextOccurence != NULL) {
                seen++;
                strncat(temp, lastOccurence, nextOccurence-lastOccurence); //Cat to temp from lastOccurence to nextOccurence
                strcat(temp, replacement); //Cat the replacement
                lastOccurence = nextOccurence+strlen(key); //Change lastOccurence to currentOccurence 
                nextOccurence = strstr(nextOccurence+1, key); //nextOccurence to the actual next occurence
        }
        strcat(temp, lastOccurence); //Cat from the last occurence to the end of payload to temp
	strncpy(payload, temp, strlen(temp)); //Assign to payload temp
	payload[strlen(temp)] = '\0'; //Cat the null char
	kfree(temp);
	return seen; //Return replacements 
}

static struct nf_hook_ops netfilter_ops_in; //NF_INET_PRE_ROUTING
static struct nf_hook_ops netfilter_ops_out; //NF_INET_POST_ROUTING
//Modify this function how you please to change what happens to incoming packets
unsigned int in_hook(void *priv, struct sk_buff * skb, const struct nf_hook_state *state) {
	/* TCP and IP headers */
	struct tcphdr *tcph = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	/* Structure that will be assigned to the seq and ack tables when needed */
	struct entry t;
	/* char * to end of payload, beginning of payload and an iterator */
	unsigned char *tail, *user_data, *it;
	/* char * to store the payload */
	char *payload;
	/* Length of original payload, length of tcp header, number of replacements done to payload
	 * the sequence and acknowledgement offsets, multipurpose iterator (for loops, while, etc) */
	int lenOrig, tcp_len, replacements, offset, i;
	/* Source port, destination port and the ip header length */
	__u16 sport, dport, ip_len;
	/* Source IP address and destination IP address */
	__u32 saddr, daddr;
	/* Sequence and acknowledgement numbers */
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

		/* If keyToReplace or replacementForKey weren't passed in, don't change the packet
		 * and if we're not changing anything, just accept it anyways */
		if (!keyToReplace || !replacementForKey) {
			return NF_ACCEPT;
		}

		/* Change the payload data stored in char * payload */
		replacements = payloadFind(payload, keyToReplace, replacementForKey);

		/* If the acknowledgement table doesn't have an entry for the source IP
		 * create an entry and store it in both the sequence and acknowledgement table 
		 * with a default offset of 0 */
		if (!getVal(seqTable, saddr)) {
			t.ip = saddr;
			t.offset = 0;
			storeVal(ackTable, t);
			storeVal(seqTable, t);
		}
		/* Same as the the above statement except for the destination IP */
		if (!getVal(ackTable, daddr)) {
			t.ip = daddr;
			t.offset = 0;
			storeVal(ackTable, t);
			storeVal(seqTable, t);
		}

		/* Change sequence number from network to host, add offset, back to network */
		seq = ntohl(tcph->seq);
		seq += getVal(seqTable, saddr)->offset;
		tcph->seq = htonl(seq);
		
		/* Change acknowledgement number from network to host, add offset, back to network */
		ack = ntohl(tcph->ack_seq);
		ack += getVal(ackTable, saddr)->offset;
		tcph->ack_seq = htonl(ack);

		/* If the length of the outgoing packet is different from the original payload
		 * the acknowledgement and sequence numbers will be off. This will cause the two 
		 * computers to start arguing amongst each other.  The offset between the correct
		 * acknowledgement and sequence number is the difference between the old payload 
		 * and the new payload + all the past difference.
		 *
		 * So add the new difference to the offset for all future packets */
		if (strlen(payload) != lenOrig) {
			offset = strlen(payload)-lenOrig;
			t.ip = saddr;
			t.offset = getVal(seqTable, saddr)->offset + offset;
			storeVal(seqTable, t);
			t.ip = daddr;
			t.offset = getVal(ackTable, daddr)->offset - offset;
			storeVal(ackTable, t);
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
		/* THIS BREAKS IF THE PAYLOAD IS NOT ASCII */
		skb_put(skb, strlen(payload)-lenOrig);

		/* memcpy into user_data the modified payload */
		user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
		memcpy(user_data, payload, strlen(payload));

		/* Convert the ip length from the network, change it to the new length, back to network */
		ip_len = ntohs(iph->tot_len);
		ip_len += strlen(payload)-lenOrig;
		iph->tot_len = htons(ip_len);

		/* Update TCP and IP checksums */
		/* THIS DOESNT WORK ON NON LINEAR SKB */
		tcp_len = skb->len - 4 * iph->ihl;
		iph->ttl += 1;
		ip_send_check(iph);
		tcph->check = 0;
		tcph->check = tcp_v4_check(tcp_len, iph->saddr, iph->daddr, csum_partial((char *)tcph, tcp_len, 0));

	}
	kfree(payload);
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
	return 0;
}

void cleanup_module() {
	nf_unregister_hook(&netfilter_ops_in);
	nf_unregister_hook(&netfilter_ops_out);
}
