#ifndef _OPENGFW_HTTP_H
#define _OPENGFW_HTTP_H

#include <linux/types.h>

int og_http_extract_host(void *packet, size_t packet_len, char **host, size_t *host_len);

int og_http_handler(void *buf, size_t buf_len);

#endif // _OPENGFW_HTTP_H