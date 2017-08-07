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
	struct tcphdr *tcph = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *modtcph;
	unsigned char *tail;
	unsigned char *user_data;
	unsigned char *it;
	struct sk_buff * modskb;
	char * tempPay;
	char * payload;
	int lenOrig;
	int lenNew;
	bool first = 0;
	u16 sport, dport;
	u32 saddr, daddr;
	tempPay = kmalloc(1500, GFP_KERNEL);
	payload = kmalloc(1500, GFP_KERNEL);
	if (!skb)
		return NF_ACCEPT;
	saddr = ntohl(iph->saddr);
	daddr = ntohl(iph->daddr);
	sport = ntohs(tcph->source);
	dport = ntohs(tcph->dest);
	tail = skb_tail_pointer(skb);
	user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
	//skb_unshare(skb, GFP_ATOMIC);
	//Add whatever IP you are interested in, currently Alberto's 2 VM's
	//IP needs to be in integer form, google a converter
	if(saddr == 167772684 || saddr == 167772685) {
		lenOrig = 0;
		for (it = user_data; it != tail; ++it) {
			char c = *(char *)it;
			if (!first) {
				//printk("TCP Check before: %d\n", tcph->check);
				*it = 'h';
				tcph->check -= ('h' - 'a');
				//printk("TCP Check after: %d\n", tcph->check);
			}
			first = 1;
			payload[lenOrig] = c;
			lenOrig++;
		}
		payload[lenOrig] = '\0';
		printk("NETFILTER.C: DATA OF ORIGINAL SKB: %s", payload);
		iph->ttl += 1;
		ip_send_check(iph);
		if (!skb->sk) {
			printk("socket is null\n");
		}
		else {
			//tcp_v4_send_check(skb->sk, skb);
		}
		payloadFind(payload, "a", "b");
		/* Everything from here forward is complete guess work, if this works, don't expect it to work forever
		If it doesn't work, I will not be surprised. */
		modskb = (struct sk_buff *)skb_copy_expand(skb, 0, strlen(payload)-skb_tailroom(skb), GFP_ATOMIC);
		modtcph = tcp_hdr(modskb);
		user_data = (unsigned char *)((unsigned char *)modtcph + (modtcph->doff * 4));
		skb_put(modskb, strlen(payload)-lenOrig);
		memcpy(user_data, payload, strlen(payload));
		lenNew = 0;
		tail = skb_tail_pointer(modskb);
		if (!tail) {
			printk("tail is null");
		}
		if (!modskb) {
			printk("modskb is null");
		}
		if (!modtcph) {
			printk("modtcph");
		}
		//printk("payload size %li" , sizeof(payload));
		//printk("tempPay size %li", sizeof(tempPay));
		for (it = user_data; it != tail; ++it) {
			char c = *(char *)it;
			if (c) {
				tempPay[lenNew] = c;
				lenNew++;
			}
			else {
				printk("Char is null\n");
			}
		}
		//printk("NETFILTER.C: LEN New = %d\n", lenNew);
		tempPay[lenNew] = '\0';
		//printk("NETFILTER.C: DATA OF MODSKB: %s", tempPay);
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
	saddr = ntohl(iph->saddr);
	if (saddr == 3232249857) {
		return NF_ACCEPT;
	}
	user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
	tail = skb_tail_pointer(skb);
	if(saddr == 167772684 || saddr == 167772685) {
		printk("NETFILTER.C: OUTGOING PACKET DATA: ");
		for (it = user_data; it != tail; ++it) {
			char c = *(char *)it;
			if (c == '\0') {
				break;
			}
			printk("%c", c);
		}
		if (!skb->sk) {
			printk("sk is null on outgoing hook");
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
