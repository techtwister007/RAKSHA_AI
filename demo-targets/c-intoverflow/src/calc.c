#include "calc.h"

/* A trivial "folding" accumulator with a classic signed-integer-overflow (CWE-190): it sums
 * the input bytes and then squares the sum into a signed int with no range check. A long,
 * high-valued input makes the sum large enough that sum*sum overflows INT_MAX, which
 * UndefinedBehaviorSanitizer (-fsanitize=undefined) reports as "signed integer overflow".
 *
 * Benign path: short inputs keep the sum small, so sum*sum stays well inside int and no
 * overflow fires — which is what the gate's differential/benign corpus relies on. */
int fold(const unsigned char *data, int len) {
    int sum = 0;
    for (int i = 0; i < len; i++) sum += data[i];
    return sum * sum;              /* BUG: unguarded signed multiply overflows for a large sum */
}
