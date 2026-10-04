#include "store.h"
#include <stdlib.h>
#include <string.h>

/* A tiny "cache" with a memory leak (CWE-401) on one input path. stash() always allocates a
 * copy of the record; on the benign path it frees the copy before returning, but when the
 * first byte is 'X' it returns early and never frees — the allocation is lost, which
 * LeakSanitizer (-fsanitize=leak) reports as a direct leak at exit.
 *
 * Benign path: any input whose first byte is not 'X' frees its copy, so a corpus of those is
 * leak-free and the gate's differential set stays clean. */
int stash(const unsigned char *data, int len) {
    char *copy = (char *) malloc((size_t) len + 1);
    if (!copy) return -1;
    memcpy(copy, data, (size_t) len);
    copy[len] = '\0';
    if (len > 0 && data[0] == 'X') {
        return len;                 /* BUG: 'copy' is never freed on this path — leaked */
    }
    int r = (int) copy[0];
    free(copy);
    return r;
}
