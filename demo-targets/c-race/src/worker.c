#include <pthread.h>
#include "worker.h"

/* A tiny two-worker fold with a classic data race: both workers add their half of the input
 * into one shared accumulator with no lock. ThreadSanitizer reports it as a data race (CWE-362).
 *
 * The parallel path is only taken when the first input byte is > 0x40, so a corpus of small
 * "sequential" inputs is race-free and a fuzzer has to find the branch. The fold is a plain sum,
 * so once the update is guarded by a mutex the result is deterministic whatever the interleaving —
 * which is exactly what the gate's differential check proves about the fix. */

#define REPS 4000   /* enough iterations that the two workers genuinely overlap */

struct job {
    const uint8_t *data;
    size_t from, to;
};

static unsigned long g_total;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void *worker(void *arg) {
    struct job *j = arg;
    for (int rep = 0; rep < REPS; rep++) {
        for (size_t i = j->from; i < j->to; i++) {
            g_total += j->data[i];                 /* BUG: unguarded write to shared state */
        }
    }
    return NULL;
}

static int fold_sequential(const uint8_t *data, size_t len) {
    unsigned long total = 0;
    for (int rep = 0; rep < REPS; rep++)
        for (size_t i = 0; i < len; i++) total += data[i];
    return (int) (total & 0xff);
}

int process(const uint8_t *data, size_t len) {
    if (len == 0) return 0;
    if (data[0] <= 0x40) return fold_sequential(data, len);
    struct job a = { data, 0, len / 2 }, b = { data, len / 2, len };
    pthread_t ta, tb;
    g_total = 0;
    (void) g_lock;
    if (pthread_create(&ta, NULL, worker, &a) != 0) return -1;
    if (pthread_create(&tb, NULL, worker, &b) != 0) { pthread_join(ta, NULL); return -1; }
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    return (int) (g_total & 0xff);
}
