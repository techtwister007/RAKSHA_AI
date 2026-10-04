/* Hand-written replay harness: read an input file, feed its bytes to fold().
 * Built with -fsanitize=undefined so a signed-integer overflow inside fold() prints a
 * UBSan "runtime error: signed integer overflow" line that UbsanOracle parses. */
#include <stdio.h>
#include <stdlib.h>
#include "src/calc.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: harness <input>\n"); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }
    unsigned char data[65536];
    size_t n = fread(data, 1, sizeof data, f);
    fclose(f);
    int r = fold(data, (int) n);
    printf("fold=%d\n", r);
    return 0;
}
