//Also, please don't touch this.  It's supposed to drop all packets eventually
//Drops any packet
#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
static struct nf_hook_ops netfilter_ops_in; //NF_IP_PRE_ROUTING
static struct nf_hook_ops netfilter_ops_out; //NF_IP_POST_ROUTING
//**skb is a pointer to a socket kernel buffer
//*in and *out are netdevice pointers
//last parameter is a function that takes a pointer to an sk_buff
unsigned int main_hook(unsigned int hooknum, struct sk_buff **skb, 
		       const struct net_device *in, 
		       const struct net_device *out,
		       int (*okfn)(struct sk_buff*)) {
	puts("Hey, we dropped a packet, we didn't need it anyways!");
	return NF_DROP; //Drop ALL packets
}
int init_module() {
	netfilter_ops_in.hook = main_hook;
	netfilter_ops_in.pf = PF_INET;
	netfilter_ops_in.hooknum = NF_IP_PRE_ROUTING;
	netfilter_ops_in.priority = NF_IP_PRI_FIRST;
	netfilter_ops_out.hook = main_hook;
	netfilter_ops_out.pf = PF_INET;
	netfilter_ops_out.hooknum = NF_IP_PRE_ROUTING;
	netfilter_ops_out.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&netfilter_ops_in);
	nf_register_hook(&netfilter_ops_out);
	return 0;
}
void cleanup() {
	nf_unregister_hook(&netfilter_ops_in);
	nf_unregister_hook(&netfiler_ops_out);
}
