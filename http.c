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

int og_http_extract_host(void *packet, size_t packet_len, char **host, size_t *host_len)
{
    void *host_field, *start, *end;

    host_field = memmem(packet, packet_len, "\r\nHost: ", 8);
    if (!host_field)
        return 1; // No host field

    start = host_field + 8;
    end = memmem(start, packet_len - (start - packet), "\r\n", 2);
    if (!end)
        return 1; // No end of line after host field??

    *host = start;
    *host_len = end - start;
    return 0;
}

int og_http_handler(void *buf, size_t buf_len)
{
    char *host;
    size_t host_len;

    if (buf_len < 16)
        return OG_TCP_ACCEPT; // Too short to be a HTTP request

    if (og_http_extract_host(buf, buf_len, &host, &host_len))
        return OG_TCP_ACCEPT;

    printk(KERN_INFO LOG_PREFIX "host: %.*s\n", host_len, host);

    if (host_len == 11 && memcmp(host, "example.com", 11) == 0)
    {
        printk(KERN_INFO LOG_PREFIX "example.com blocked\n");
        return OG_TCP_RESET;
    }

    return OG_TCP_ACCEPT;
}