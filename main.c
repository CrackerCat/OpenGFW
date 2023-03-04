#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>

#include "http.h"

#include "utils.h"

static struct nf_hook_ops *nf_dispatch_ops = NULL;

static unsigned int nf_dispatch(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    size_t tcp_payload_len;
    void *buf_tmp = NULL;
    unsigned int action = NF_ACCEPT;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    tcph = tcp_hdr(skb);

    tcp_payload_len = skb->len - skb_transport_offset(skb) - tcph->doff * 4;
    if (!tcp_payload_len)
        return NF_ACCEPT; // No payload

    // Dispatch
    if (skb_is_nonlinear(skb))
    {
        // Nonlinear skb, copy to linear buffer
        buf_tmp = kmalloc(tcp_payload_len, GFP_KERNEL);
        if (!buf_tmp)
            return NF_ACCEPT;
        if (skb_copy_bits(skb, skb_transport_offset(skb) + tcph->doff * 4, buf_tmp, tcp_payload_len))
        {
            kfree(buf_tmp);
            return NF_ACCEPT;
        }
    }
    else
    {
        buf_tmp = (void *)tcph + tcph->doff * 4;
    }

    switch (og_http_handler(buf_tmp, tcp_payload_len))
    {
    case OG_TCP_DROP:
        action = NF_DROP;
        break;
    case OG_TCP_ACCEPT:
        action = NF_ACCEPT;
        break;
    case OG_TCP_RESET:
        action = NF_ACCEPT;
        tcph->rst = 1; // Not working, TODO
        break;
    }

    if (buf_tmp != (void *)tcph + tcph->doff * 4)
        kfree(buf_tmp);

    return action;
}

static int __init nf_opengfw_init(void)
{
    nf_dispatch_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_dispatch_ops == NULL)
    {
        printk(KERN_INFO LOG_PREFIX "failed to allocate memory for nf_dispatch_ops\n");
        return -1;
    }
    nf_dispatch_ops->hook = (nf_hookfn *)nf_dispatch;
    nf_dispatch_ops->hooknum = NF_INET_POST_ROUTING;
    nf_dispatch_ops->pf = NFPROTO_IPV4;
    nf_dispatch_ops->priority = NF_IP_PRI_FILTER;

    if (nf_register_net_hook(&init_net, nf_dispatch_ops))
    {
        printk(KERN_INFO LOG_PREFIX "failed to register hook\n");
        kfree(nf_dispatch_ops);
        return -1;
    }

    printk(KERN_INFO LOG_PREFIX "loaded\n");
    return 0;
}

static void __exit nf_opengfw_exit(void)
{
    if (nf_dispatch_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_dispatch_ops);
        kfree(nf_dispatch_ops);
    }

    printk(KERN_INFO LOG_PREFIX "unloaded\n");
}

module_init(nf_opengfw_init);
module_exit(nf_opengfw_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tobyxdd");
MODULE_DESCRIPTION("OpenGFW");
