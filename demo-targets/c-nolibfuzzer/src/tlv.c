/* A tiny TLV (tag-length-value) record parser. No fuzz harness ships with it — RAKSHA must
 * synthesize one, find the overflow, fix it and prove the fix. The bug: `length` comes from the
 * input and is copied into a fixed 32-byte stack buffer with no bound against sizeof(value). */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int parse_record(const uint8_t *data, size_t len) {
    if (len < 2) return -1;
    uint8_t tag = data[0];
    size_t length = data[1];
    char value[32];
    if (tag == 0x01) {
        size_t n = (length <= len - 2) ? length : (len - 2);  /* clamp to available input... */
        memcpy(value, data + 2, n);                           /* ...but not to sizeof(value): BUG */
        return value[0];
    }
    return 0;
}
