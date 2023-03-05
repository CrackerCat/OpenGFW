#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/ctype.h>

#include "http.h"

#include "utils.h"

static char *hostlist_str = NULL;

struct hostlist_entry
{
    char host[256];
    struct hostlist_entry *next;
};

static struct hostlist_entry *hostlist_head = NULL, *hostlist_tail = NULL;

static void hostlist_empty(void)
{
    struct hostlist_entry *entry = hostlist_head, *next;
    while (entry)
    {
        next = entry->next;
        kfree(entry);
        entry = next;
    }
    hostlist_head = NULL;
    hostlist_tail = NULL;
}

static int hostlist_param_set(const char *val, const struct kernel_param *kp)
{
    size_t val_len = strlen(val);
    const char *start = val, *end;
    size_t len;
    struct hostlist_entry *new_entry;

    while (val_len > 0 && (val[val_len - 1] == '\n' || val[val_len - 1] == '\r'))
        val_len--;

    hostlist_empty();

    while (start < val + val_len)
    {
        end = strchr(start, ',');
        if (!end)
            end = val + val_len;

        len = end - start;
        if (len == 0 || len >= sizeof(new_entry->host))
        {
            // Ignore empty or too long host
            start = end + 1;
            continue;
        }

        new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
        if (!new_entry)
            return -ENOMEM;

        strncpy(new_entry->host, start, len);
        new_entry->host[len] = '\0';

        new_entry->next = NULL;
        if (!hostlist_tail)
        {
            hostlist_head = new_entry;
            hostlist_tail = new_entry;
        }
        else
        {
            hostlist_tail->next = new_entry;
            hostlist_tail = new_entry;
        }

        start = end + 1;
    }

    return 0;
}

static int hostlist_param_get(char *buffer, const struct kernel_param *kp)
{
    struct hostlist_entry *entry = hostlist_head;
    int len = 0;

    while (entry)
    {
        len += snprintf(buffer + len, PAGE_SIZE - len,
                        (entry->next ? "%s," : "%s\n"),
                        entry->host);
        entry = entry->next;
    }

    return len;
}

static struct kernel_param_ops hostlist_param_ops = {
    .set = hostlist_param_set,
    .get = hostlist_param_get,
};

module_param_cb(http_hosts, &hostlist_param_ops, &hostlist_str, 0600);

static bool wildcard_match(const char *haystack, size_t haystack_len, const char *pattern)
{
    const char *p = pattern;
    const char *last_s = NULL;
    const char *last_p = NULL;
    while (haystack_len > 0)
    {
        if (*p == '*')
        {
            last_s = haystack;
            last_p = p++;
        }
        else if (*p == '?' || *haystack == *p)
        {
            haystack++;
            p++;
            haystack_len--;
        }
        else if (last_s != NULL)
        {
            haystack = ++last_s;
            p = last_p + 1;
            haystack_len--;
        }
        else
        {
            return false;
        }
    }
    while (*p == '*')
        p++;
    return *p == '\0';
}

static int og_http_extract_host(void *packet, size_t packet_len, char **host, size_t *host_len)
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

static int og_https_extract_host(void *rp, size_t packet_len, char **host, size_t *host_len)
{
    unsigned char *packet = rp;
    size_t len;
    size_t ch_len;
    size_t pos;
    size_t ext_len;
    size_t ext_type;
    size_t ext_size;

    if (packet[0] != 0x16 || packet[1] != 0x03 || packet[5] != 0x01)
        return 1; // Not a TLS Client Hello

    len = (packet[3] << 8) | packet[4];
    ch_len = (packet[6] << 16) | (packet[7] << 8) | packet[8];

    if (ch_len > len || len > packet_len)
        return 1; // Length sanity check

    pos = 43;                                          // session_id length
    pos += 1 + packet[pos];                            // Skip session_id
    pos += 2 + ((packet[pos] << 8) | packet[pos + 1]); // Skip cipher_suites
    pos += 1 + packet[pos];                            // Skip compression_methods

    if (pos + 2 > ch_len)
        return 1; // Length sanity check

    ext_len = (packet[pos] << 8) | packet[pos + 1];
    pos += 2;

    while (pos < ch_len)
    {
        if (pos + 4 > ch_len)
            return 1; // Length sanity check

        ext_type = (packet[pos] << 8) | packet[pos + 1];
        ext_size = (packet[pos + 2] << 8) | packet[pos + 3];
        pos += 4;

        if (ext_type == 0x0000)
        {
            // Server Name Indication
            // We skip list length & type for now, assume it's a host_name
            pos += 3;
            *host_len = (packet[pos] << 8) | packet[pos + 1];
            *host = &packet[pos + 2];
            return 0;
        }

        pos += ext_size;
    }

    return 1; // No host extension found
}

// og_http_handler handles both HTTP and HTTPS
int og_http_handler(void *buf, size_t buf_len)
{
    char *host;
    size_t host_len;

    if (buf_len < 16)
        return OG_TCP_ACCEPT; // Too short

    if (og_https_extract_host(buf, buf_len, &host, &host_len) &&
        og_http_extract_host(buf, buf_len, &host, &host_len))
        return OG_TCP_ACCEPT; // No host found

    if (hostlist_head)
    {
        struct hostlist_entry *entry = hostlist_head;
        while (entry)
        {
            if (wildcard_match(host, host_len, entry->host))
            {
                printk(KERN_INFO LOG_PREFIX "blocking host %.*s", (int)host_len, host);
                return OG_TCP_DROP;
            }
            entry = entry->next;
        }
    }

    return OG_TCP_ACCEPT;
}