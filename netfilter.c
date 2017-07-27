#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/tcp.h>
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
//EQUIVALENT TO PCAP CALLBACK
unsigned int in_hook(void *priv, struct sk_buff * skb, const struct nf_hook_state *state) {
	struct tcphdr *tcph = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *modtcph;
	struct iphdr *modiph;
	unsigned char *tail;
	unsigned char *user_data;
	unsigned char *it;
	struct sk_buff * modskb;
	char * tempPay;
	char * payload;
	int len;
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
	user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
	tail = skb_tail_pointer(skb);
	if (saddr == 3232249857) {
		return NF_ACCEPT;
	}
	//Add whatever IP you are interested in, currently Alberto's 2 VM's
	//IP needs to be in integer form, google a converter
	if(saddr == 3232249868 || saddr == 3232249869) {
		len = 0;
		for (it = user_data; it != tail; ++it) {
			char c = *(char *)it;
			payload[len] = c;
			len++;
		}
		payload[len] = '\0';
		printk("NETFILTER.C: DATA OF ORIGINAL SKB: %s", payload);
		payloadFind(payload, "a", "b");
		//printk("NETFILTER.C: REPLACED DATA: %s", payload);
		/* Everything from here forward is complete guess work, if this works, don't expect it to work forever
		If it doesn't work, I will not be surprised. */
		modskb = (struct sk_buff *)skb_copy_expand(skb, 0, strlen(payload) - skb_tailroom(skb), GFP_ATOMIC);
		modtcph = tcp_hdr(modskb);
		user_data = (unsigned char *)((unsigned char *)modtcph + (modtcph->doff * 4));
		skb_put(modskb, strlen(payload)-1);
		memcpy(user_data, payload, strlen(payload));
		skb = modskb;
		len = 0;
		tail = skb_tail_pointer(modskb);
		for (it = user_data; it != tail; ++it) {
			char c = *(char *)it;
			tempPay[len] = c;
			len++;
		}
		//Somewhere after here, something causes a kernel panic
		tempPay[len] = '\0';
		printk("NETFILTER.C: DATA OF MODSKB: %s", tempPay);
	}
	return NF_ACCEPT;
}
//Modify this function how you please to change what happens to outgoing packets
//Does nothing at the moment
unsigned int out_hook(void *priv, struct sk_buff * skb, const struct nf_hook_state *state) {
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
