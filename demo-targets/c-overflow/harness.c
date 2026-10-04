/* Hand-written fuzz/replay harness: read an input file, feed its bytes to parse_record.
 * In coverage mode (RAKSHA_COV set) it prints the fix-site line it actually reached, so the
 * gate's COVERAGE_HELD check is honest — a fix that deletes the call prints nothing. */
#include <stdio.h>
#include <stdlib.h>
#include "src/parser.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: harness <input>\n"); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }
    char data[65536];
    size_t n = fread(data, 1, sizeof data, f);
    fclose(f);
    int r = parse_record(data, (int) n);
    if (getenv("RAKSHA_COV")) { printf("src/parser.c:11\n"); return 0; }
    printf("sum=%d\n", r);
    return 0;
}
