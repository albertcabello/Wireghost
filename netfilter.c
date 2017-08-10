#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<net/ip.h>
#include<net/tcp.h>
//Array ack_table; //This is the table that will store the acknoledgment numbers
//Array seq_table; //This is the table that will store sequence numbers
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
//IF THE COMPUTER EVER STARTS CRASHING IN THIS PROGRAM, IT IS PROBABLY BECAUSE OF THIS
//STRNCPY MAY BREAK SOMETHING ONE DAY, BE WARNED 
void payloadFind(char* payload, const char* key, const char* replacement) {
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
}

static struct nf_hook_ops netfilter_ops_in; //NF_INET_PRE_ROUTING
static struct nf_hook_ops netfilter_ops_out; //NF_INET_POST_ROUTING
//Modify this function how you please to change what happens to incoming packets
unsigned int in_hook(void *priv, struct sk_buff * skb, const struct nf_hook_state *state) {
	//Couple lines need to be pasted
	struct tcphdr *modtcph, *tcph = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct sk_buff * modskb;
	unsigned char *tail, *user_data, *it;
	char * tempPay, *payload;
	int lenOrig, lenNew, tcp_len;
	__u16 sport, dport, ip_len;
	__u32 saddr, daddr;
	payload = tempPay = kmalloc(1500, GFP_KERNEL);

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

	/* Filter all IP's except those we are interested in
	   for now must be in integer form */
	if(saddr == 167772684 || saddr == 167772685) {
		//skb_unshare(skb, GFP_ATOMIC); //Must unshare the skb to modify it

		/* Loops through the skb payload and stores it in char * payload */
		lenOrig = 0;
		for (it = user_data; it != tail; ++it) {
			char c = *(char *)it;
			payload[lenOrig] = c;
			lenOrig++;
		}
		payload[lenOrig] = '\0';

		
		printk("NETFILTER.C: DATA OF ORIGINAL SKB: %s", payload);
		

		/* Change the payload data stored in char * payload */
		payloadFind(payload, "a", "xyz");


		/* Creates a new skb: modskb
		   modskb is an exact copy with the exception that it's payload
		   area is large enough to hold the modified payload. */
		modskb = (struct sk_buff *)skb_copy_expand(skb, 0, strlen(payload)-skb_tailroom(skb), GFP_ATOMIC);
		modtcph = tcp_hdr(modskb);
		skb_put(modskb, strlen(payload)-lenOrig);

		/* Same as above, user_data is the beginning of modskb's payload
		   tail is the end of it. */
		user_data = (unsigned char *)((unsigned char *)modtcph + (modtcph->doff * 4));
		tail = skb_tail_pointer(modskb);

		/* memcpy into user_data the new payload */
		memcpy(user_data, payload, strlen(payload));

		/* Loops through the modskb payload and stores it in char * tempPay */
		lenNew = 0;
		for (it = user_data; it != tail; ++it) {
			char c = *(char *)it;
			tempPay[lenNew] = c;
			lenNew++;
		}
		tempPay[lenNew] = '\0';


		printk("NETFILTER.C: DATA OF MODSKB: %s", tempPay);

		if(pskb_expand_head(skb, 0, strlen(payload)-skb_tailroom(skb), GFP_ATOMIC)) {
			printk("Sorry, we couldn't expand the skb, you'll just have to accept it\n");
			return NF_ACCEPT;
		}
		tcph = tcp_hdr(skb);
		iph = ip_hdr(skb);
		skb_put(skb, strlen(payload)-lenOrig);
		user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
		memcpy(user_data, payload, strlen(payload));

		/* Fix the ip header ttl because the spoofing takes away one
		   Update the TCP and IP headers.  
		   This does not work on non-linear skb's, will need to be fixed soon */
		ip_len = ntohs(iph->tot_len);
		ip_len += strlen(payload)-lenOrig;
		iph->tot_len = htons(ip_len);
		tcp_len = skb->len - 4 * iph->ihl;
		iph->ttl += 1;
		ip_send_check(iph);
		tcph->check = 0;
		tcph->check = tcp_v4_check(tcp_len, iph->saddr, iph->daddr, csum_partial((char *)tcph, tcp_len, 0));

	}
	return NF_ACCEPT;
}
//Modify this function how you please to change what happens to outgoing packets
//Does nothing at the moment
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
	if(saddr == 167772684 || saddr == 167772685) {

		/* Loop through the skb payload and print it */
		printk("NETFILTER.C: OUTGOING PACKET DATA: ");
		for (it = user_data; it != tail; ++it) {
			char c = *(char *)it;
			if (c == '\0') {
				break;
			}
			printk("%c", c);
		}
		printk("\n");

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
	//Add array initializers	
	return 0;
}
void cleanup_module() {
	nf_unregister_hook(&netfilter_ops_in);
	nf_unregister_hook(&netfilter_ops_out);
}
