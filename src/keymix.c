#include "keymix.h"

#include "config.h"
#include "types.h"
#include "utils.h"
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define CHECKED(F)                                                                                 \
        err = F;                                                                                   \
        if (err)                                                                                   \
                goto cleanup;

// Mixes the seed into out
int keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config) {
        byte *buffer = (byte *)malloc(seed_size);

        int err             = 0;
        size_t nof_macros   = seed_size / SIZE_MACRO;
        unsigned int levels = 1 + (unsigned int)(log(nof_macros) / log(config->diff_factor));

        // seed -> (mixctr) -> out
        CHECKED((*(config->mixfunc))(seed, out, seed_size));

        for (unsigned int level = 1; level < levels; level++) {
                // out -> (swap) -> buffer
                swap(buffer, out, seed_size, level, config->diff_factor);
                D printf("encrypt level %d\n", level);
                // buffer -> (mixctr) -> out
                CHECKED((*(config->mixfunc))(buffer, out, seed_size));
        }
cleanup:
        explicit_bzero(buffer, seed_size);
        free(buffer);
        return err;
}

#undef CHECKED

void *run(void *config) {
        thread_data *args  = (thread_data *)config;
        int *thread_status = malloc(sizeof(int));
        *thread_status     = 0;
        if (thread_status == NULL) {
                D printf("thread %d crashed at init time\n", args->thread_id);
                *thread_status = ENOMEM;
                goto thread_exit;
        }

        for (unsigned int l = 0; l < args->thread_levels; l++) {
                if (l) {
                        shuffle_opt(args->swp, args->out, args->thread_chunk_size, l, args->diff_factor);
                }
                D printf("thread %d encrypting level %d\n", args->thread_id, l);
                *thread_status = (*(args->mixfunc))(args->swp, args->out, args->thread_chunk_size);
                if (*thread_status) {
                        printf("[e] thread %d encryption error\n", args->thread_id);
                        goto thread_exit;
                }
        }
        D printf("thread %d finished the thread-layers\n", args->thread_id);
        // notify the coordinator
        if (args->thread_levels != args->total_levels) {
                while (1) {
                        *thread_status = sem_post(args->coord_sem);
                        if (*thread_status == 0) {
                                break;
                        }
                }
        }
        // synchronized encryption layers
        for (unsigned int l = args->thread_levels; l < args->total_levels; l++) {
                *thread_status = 0;
                // synchronized swap
                while (1) {
                        *thread_status = sem_wait(args->thread_sem);
                        if (*thread_status == 0) {
                                D printf("thread %d sychronized swap, level %d\n", args->thread_id,
                                         l - 1);
                                shuffle_chunks(args, l);
                                break;
                        }
                }
                // notify the coordinator
                while (1) {
                        *thread_status = sem_post(args->coord_sem);
                        if (*thread_status == 0) {
                                D printf("thread %d notified the coordinator after swap\n",
                                         args->thread_id);
                                break;
                        }
                }
                // synchronized encryption
                while (1) {
                        *thread_status = sem_wait(args->thread_sem);
                        if (*thread_status == 0) {
                                D printf("thread %d sychronized encryption, level %d\n",
                                         args->thread_id, l);
                                *thread_status = (*(args->mixfunc))(args->swp, args->out,
                                                                    args->thread_chunk_size);
                                if (*thread_status != 0) {
                                        goto thread_exit;
                                }
                                break;
                        }
                }
                // notify the coordinator
                while (1) {
                        *thread_status = sem_post(args->coord_sem);
                        if (*thread_status == 0) {
                                D printf("thread %d notified the coordinator after encryption\n",
                                         args->thread_id);
                                break;
                        }
                }
        }
thread_exit:
        pthread_exit(thread_status);
}

void free_thread_sems(thread_data *args, unsigned int threads) {
        int err;
        for (unsigned int t = 0; t < threads; t++) {
                err = sem_destroy(args[t].thread_sem);
                if (err != 0) {
                        D printf("sem_free error (thread_sems)\n");
                }
                free(args[t].thread_sem);
        }
}

void free_coord_sems(thread_data *args, unsigned int threads) {
        int err;
        for (unsigned int t = 0; t < threads; t++) {
                err = sem_destroy(args[t].coord_sem);
                if (err != 0) {
                        D printf("sem_free error (coord sems)\n");
                }
                free(args[t].coord_sem);
        }
}

// Mixes the seed into out using a number of threads equal to a power of diff_factor
int parallel_keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config,
                    unsigned int nof_threads) {

        int routine_errno = 0;

        if (nof_threads < 1 || nof_threads > 128) {
                D printf("Unsupported number of threads\n");
                return EPERM;
        }

        size_t nof_macros = seed_size / SIZE_MACRO;
        unsigned int thread_levels =
            1 + log10(((double)nof_macros) / nof_threads) / log10(config->diff_factor);
        unsigned int total_levels =
            1 + (unsigned int)(log10(nof_macros) / log10(config->diff_factor));

        D printf("thread levels:\t\t%d\n", thread_levels);
        D printf("total levels:\t\t%d\n", total_levels);

        pthread_t threads[nof_threads];
        thread_data args[nof_threads];
        // todo: explicit check
        size_t thread_chunk_size = seed_size / nof_threads;

        byte *swp = checked_malloc(seed_size);

        int tmp_ret = 0;
        D printf("[i] preparing the threads\n");
        for (unsigned int t = 0; t < nof_threads; t++) {
                args[t].thread_id  = t;
                args[t].thread_sem = malloc(sizeof(sem_t));
                if (args[t].thread_sem == NULL) {
                        routine_errno = ENOMEM;
                        nof_threads   = t; // shorten the list to be cleaned
                        goto full_cleanup;
                }
                tmp_ret = sem_init(args[t].thread_sem, 0, 0);
                if (tmp_ret != 0) {
                        D printf("sem_init error (thread_sem), try again\n");
                        routine_errno = errno;
                        nof_threads   = t;
                        goto full_cleanup;
                }
                args[t].coord_sem = malloc(sizeof(sem_t));
                if (args[t].coord_sem == NULL) {
                        routine_errno = ENOMEM;
                        nof_threads   = t;
                        goto full_cleanup;
                }
                tmp_ret = sem_init(args[t].coord_sem, 0, 0);
                if (tmp_ret != 0) {
                        D printf("sem_init error (coord_sem), try again\n");
                        routine_errno = errno;
                        nof_threads   = t;
                        goto full_cleanup;
                }
                args[t].in                = seed + t * thread_chunk_size;
                args[t].out               = out + t * thread_chunk_size;
                args[t].swp               = swp + t * thread_chunk_size;
                args[t].abs_out           = out;
                args[t].abs_swp           = swp;
                args[t].seed_size         = seed_size;
                args[t].thread_chunk_size = thread_chunk_size;
                args[t].diff_factor       = config->diff_factor;
                args[t].thread_levels     = thread_levels;
                args[t].total_levels      = total_levels;
                args[t].mixfunc           = config->mixfunc;
        }

        D printf("[i] spawning the threads\n");
        for (unsigned int t = 0; t < nof_threads; t++) {
                tmp_ret = pthread_create(&threads[t], NULL, run, &args[t]);
                if (tmp_ret != 0) {
                        D printf("pthread_create error %d\n", tmp_ret);
                        routine_errno = tmp_ret;
                        goto full_cleanup;
                }
        }

        D printf("[i] init parent swapping procedure\n");

        // todo: implement timeout fail
        if (thread_levels != total_levels) {
                for (unsigned int l = 0; l < (total_levels - thread_levels) * 2 + 1; l++) {
                        unsigned int loop_ctr   = 0;
                        unsigned int thread_ctr = 0;
                        // wait until all the threads have completed the levels
                        while (1) {
                                tmp_ret = sem_trywait(args[loop_ctr].coord_sem);
                                if (tmp_ret == 0) {
                                        // todo: move its memory to other threads
                                        D printf("[i] thread %d waiting...\n", loop_ctr);
                                        thread_ctr++;
                                }
                                if (thread_ctr == nof_threads) {
                                        break;
                                }
                                loop_ctr++;
                                if (loop_ctr == nof_threads) {
                                        loop_ctr = 0;
                                }
                        }
                        for (unsigned int t = 0; t < nof_threads; t++) {
                                do {
                                        tmp_ret = sem_post(args[t].thread_sem);
                                } while (tmp_ret != 0 && errno == EINTR);
                                if (tmp_ret == -1 && errno != EINTR) {
                                        D printf("coordinator, sem_post error %d\n", errno);
                                        routine_errno = tmp_ret;
                                        goto full_cleanup;
                                }
                        }
                        D printf("[i] coordinator notified all the threads\n");
                }
        }

        D printf("[i] joining the threads...\n");
        void *retval;
        for (unsigned int t = 0; t < nof_threads; t++) {
                tmp_ret = pthread_join(threads[t], &retval);
                if (tmp_ret != 0) {
                        D printf("pthread_join error %d (thread %d)\n", tmp_ret, t);
                        routine_errno = tmp_ret;
                        goto full_cleanup;
                }
        }

full_cleanup:
        D printf("[i] safe obj destruction\n");
        explicit_bzero(swp, seed_size);
        free(swp);
        free_thread_sems(args, nof_threads);
        free_coord_sems(args, nof_threads);
partial_cleanup:
        if (retval != NULL) {
                free(retval);
        }
ret:
        return routine_errno;
}
