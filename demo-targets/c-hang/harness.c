/* Hand-written replay harness: read an input file, feed its bytes to process().
 * The hang oracle's replay is "run under a timeout; a non-return within the budget is the
 * signal", so this harness has no sanitizer — the timeout itself is the detector. */
#include <stdio.h>
#include <stdlib.h>
#include "src/loop.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: harness <input>\n"); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }
    unsigned char data[65536];
    size_t n = fread(data, 1, sizeof data, f);
    fclose(f);
    int r = process(data, (int) n);
    printf("process=%d\n", r);
    return 0;
}
