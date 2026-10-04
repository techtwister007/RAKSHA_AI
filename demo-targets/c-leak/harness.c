/* Hand-written replay harness: read an input file, feed its bytes to stash().
 * Built with -fsanitize=leak so a buffer stash() forgot to free is reported as a direct
 * leak at exit, which LeakOracle parses into a CWE-401 record. */
#include <stdio.h>
#include <stdlib.h>
#include "src/store.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: harness <input>\n"); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }
    unsigned char data[65536];
    size_t n = fread(data, 1, sizeof data, f);
    fclose(f);
    int r = stash(data, (int) n);
    printf("stash=%d\n", r);
    return 0;
}
