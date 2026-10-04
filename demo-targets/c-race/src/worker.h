#ifndef RAKSHA_WORKER_H
#define RAKSHA_WORKER_H
#include <stddef.h>
#include <stdint.h>

/* Entry point: fold the input into a one-byte digest. Inputs whose first byte is > 0x40 take the
 * parallel path (two worker threads); anything else is folded sequentially. */
int process(const uint8_t *data, size_t len);

#endif
