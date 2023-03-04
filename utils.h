#ifndef _OPENGFW_UTILS_H
#define _OPENGFW_UTILS_H

#include <linux/string.h>

#define LOG_PREFIX "OpenGFW: "

#define OG_TCP_DROP 0
#define OG_TCP_ACCEPT 1
#define OG_TCP_RESET 2

void *memmem(const void *haystack, size_t haystack_len,
             const void *needle, size_t needle_len);

#endif // _OPENGFW_UTILS_H