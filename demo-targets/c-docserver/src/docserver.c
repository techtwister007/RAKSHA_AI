/* c-docserver — a document fetcher whose defect never crashes: B12's demo target.
 *
 * Request on stdin: "doc:<name>". It serves data/<name>. The name is not checked for "..", so
 * "doc:../../../../etc/hostname" reads a file outside the document root (CWE-22). No sanitizer
 * fires — nothing overflows, nothing aborts — which is exactly why RAKSHA watches BEHAVIOUR:
 * on benign requests the target only ever opens files under data/; this one opens something new.
 */
#include <stdio.h>
#include <string.h>

int main(void) {
    char req[512];
    size_t n = fread(req, 1, sizeof(req) - 1, stdin);
    req[n] = '\0';
    char *nl = strchr(req, '\n');
    if (nl) *nl = '\0';
    if (strncmp(req, "doc:", 4) != 0) {
        puts("usage: doc:<name>");
        return 0;
    }
    char path[600];
    snprintf(path, sizeof(path), "data/%s", req + 4);   /* no ".." check: path traversal */
    FILE *f = fopen(path, "r");
    if (!f) {
        puts("not found");
        return 0;
    }
    char buf[256];
    size_t k = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    fwrite(buf, 1, k, stdout);
    return 0;
}
