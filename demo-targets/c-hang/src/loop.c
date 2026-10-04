#include "loop.h"

/* An input-triggered unbounded loop (CWE-400 resource exhaustion). On the benign path the
 * function folds the input and returns; when the first byte is 'H' it enters a loop with no
 * reachable exit and never returns, so a run under a timeout is killed rather than finishing.
 *
 * `sink` is volatile so the compiler cannot prove the loop is dead and delete it, which would
 * turn the demo's "hang" into an immediate return under optimisation. */
volatile unsigned int sink = 0;

int process(const unsigned char *data, int len) {
    if (len > 0 && data[0] == 'H') {
        while (1) { sink = sink + 1; }      /* BUG: unbounded loop, never returns on this input */
    }
    int acc = 0;
    for (int i = 0; i < len; i++) acc += data[i];
    return acc & 0xff;
}
