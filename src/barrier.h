#include <pthread.h>
#include <stdint.h>

typedef struct {
        pthread_mutex_t mutex;
        pthread_cond_t cond;
        int8_t nof_waiting_thread;
        int8_t round;
} thr_barrier_t;

// Initialize the barrier struct
int barrier_init(thr_barrier_t *state);

// Block current thread untill all threads have reached the barrier
int barrier(thr_barrier_t *state, int8_t nof_threads);

// Destruct the barrier struct
int barrier_destroy(thr_barrier_t *state);