#include "parser.h"

/* A record parser with a classic stack buffer overflow: it copies the whole input into a
 * fixed 16-byte buffer with no bounds check. An input longer than 16 bytes overflows the
 * stack, which AddressSanitizer catches as a stack-buffer-overflow (CWE-121).
 *
 * The RAKSHA fix (template lane) bounds the copy to the buffer size. The checksum loop already
 * caps at 16, so benign inputs (<= 16 bytes) produce identical output before and after the fix —
 * which is exactly what the gate's differential check proves. */
int parse_record(const char *data, int len) {
    char buf[16];
    memcpy(buf, data, len);              /* BUG: unbounded copy into a 16-byte buffer */
    int sum = 0;
    for (int i = 0; i < len && i < 16; i++) sum += (unsigned char) buf[i];
    return sum & 0xff;
}
