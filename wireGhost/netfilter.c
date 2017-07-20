//Also, please don't touch this.  It's supposed to drop all packets eventually
//Drops any packet
#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/tcp.h>
static struct nf_hook_ops netfilter_ops_in; //NF_INET_PRE_ROUTING
static struct nf_hook_ops netfilter_ops_out; //NF_INET_POST_ROUTING
//Modify this function how you please to change what happens to incoming packets
//Right now I just print the source ip address (it is correct) although it also prints the gateway address
unsigned int in_hook(unsigned int hooknum, struct sk_buff * skb,  
		       const struct net_device *in, 
		       const struct net_device *out,
		       int (*okfn)(struct sk_buff*)) {
	struct tcphdr *tcph = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	unsigned char *tail;
	unsigned char *user_data;
	unsigned char *it;
	u16 sport, dport;
	u32 saddr, daddr;
	if (!skb)
		return NF_ACCEPT;
	saddr = ntohl(iph->saddr);
	daddr = ntohl(iph->daddr);
	sport = ntohs(tcph->source);
	dport = ntohs(tcph->dest);
	user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
	tail = skb_tail_pointer(skb);
	//Add whatever IP you are interested in, currently Alberto's 2 VM's
	//IP needs to be in integer form, google a converter
	if (saddr != 3232235888 || saddr != 3232235891) { 
		return NF_ACCEPT;
	}
	printk("Source IP: %pI4", &saddr);
	printk("NETFILTER.C: DATA: ");
	for (it = user_data; it != tail; ++it) {
		char c = *(char *)it;
		if (c== '\0') {
			break;
		}
		printk("%c", c);
	}
	return NF_ACCEPT;
}
//Modify this function how you please to change what happens to outgoing packets
//Does nothing except say goodbye at the moment
unsigned int out_hook(unsigned int hooknum, struct sk_buff **skb, 
		       const struct net_device *in, 
		       const struct net_device *out,
		       int (*okfn)(struct sk_buff*)) {
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
