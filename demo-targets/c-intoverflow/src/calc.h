#ifndef RAKSHA_CALC_H
#define RAKSHA_CALC_H

/* Sum the input bytes and square the sum. Overflows signed int for a large sum. */
int fold(const unsigned char *data, int len);

#endif
