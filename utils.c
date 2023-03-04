#include <linux/string.h>

#include "utils.h"

void *memmem(const void *haystack, size_t haystack_len,
             const void *needle, size_t needle_len)
{
    const char *hay = (const char *)haystack;
    const char *ndl = (const char *)needle;
    size_t i;

    if (needle_len > haystack_len)
        return NULL;

    for (i = 0; i <= haystack_len - needle_len; ++i)
        if (memcmp(hay + i, ndl, needle_len) == 0)
            return (void *)(hay + i);

    return NULL;
}