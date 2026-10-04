#ifndef RAKSHA_STORE_H
#define RAKSHA_STORE_H

/* Copy the record into a heap buffer. Leaks the buffer when the first byte is 'X'. */
int stash(const unsigned char *data, int len);

#endif
