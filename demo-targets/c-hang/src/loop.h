#ifndef RAKSHA_LOOP_H
#define RAKSHA_LOOP_H

/* Fold the input and return — unless the first byte is 'H', which hangs forever. */
int process(const unsigned char *data, int len);

#endif
