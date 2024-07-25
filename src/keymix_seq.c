#include "keymix_seq.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keymix.h"
#include "log.h"
#include "types.h"
#include "utils.h"

// Writes to fstr_output the encrypted resource. The function can be
// simplified by reading and writing all the bytes with a single
// operation, however, that might fail on platforms where size_t is
// not large enough to store the size of min(resource_size,
// seed_size).  It seems there is no observable difference (in terms
// of performance) between using machine specific page-size vs reading
// the whole resource at once. mmap() as an alternative for fread()
// has been considered, again, apparently no particular performance
// difference for seeds larger than 10MiB.
int write_ctx_to_storage(FILE *fstr_output, FILE *fstr_resource, size_t resource_size, byte *out,
                         size_t seed_size, size_t page_size) {

        int write_status = 0;

        size_t min_size  = MIN(resource_size, seed_size);
        size_t nof_pages = min_size / page_size;
        size_t remainder = min_size % page_size;

        // fwrite is slower than fread, so xor is done in memory using
        // a temporary buffer (in the future we can avoid reallocating
        // this buffer for every T, T+1, ...)
        byte *resource_page = checked_malloc(page_size);
        size_t offset       = 0;
        for (; nof_pages > 0; nof_pages--) {
                // read the resource
                if (1 != fread(resource_page, page_size, 1, fstr_resource)) {
                        write_status = ERR_FREAD;
                        goto clean_write;
                }
                // xor the resource with the mixed key
                memxor(out + offset, resource_page, page_size);
                // write thre result to fstr_encrypted
                if (1 != fwrite(out + offset, page_size, 1, fstr_output)) {
                        write_status = ERR_FWRITE;
                        goto clean_write;
                }
                offset += page_size;
        }
        // do the previous operations for the remainder of the
        // resource (when the tail is smaller than the seed_size)
        if (remainder != fread(resource_page, 1, remainder, fstr_resource)) {
                write_status = ERR_FREAD;
                goto clean_write;
        }
        memxor(out + offset, resource_page, remainder);
        if (remainder != fwrite(out + offset, 1, remainder, fstr_output)) {
                write_status = ERR_FWRITE;
                goto clean_write;
        }

clean_write:
        explicit_bzero(resource_page, page_size);
        free(resource_page);
        return write_status;
}

int keymix_seq(struct arguments *config, FILE *fstr_output, FILE *fstr_resource, size_t page_size,
               size_t resource_size, byte *secret, size_t secret_size) {

        int status = 0;

        unsigned long epochs = (unsigned long)(ceil(((double)resource_size) / secret_size));
        if (config->verbose)
                printf("epochs:\t\t%ld\n", epochs);
        // set the mixing function
        mixing_config mix_conf = {config->mixfunc, config->diffusion};
        // prepare the memory
        byte *out = checked_malloc(secret_size);
        // apply the iv (16 bytes) to the first seed block
        memxor(secret, config->iv, SIZE_BLOCK);

        // mix T, T+1, ...
        for (unsigned long e = 0; e < epochs; e++) {
                _log(LOG_DEBUG, "~~>epoch %ld\n", e);
                // apply the counter
                if (e != 0)
                        increment_counter(secret, 1);
                status = keymix(secret, out, secret_size, &mix_conf, 1);
                if (status != 0)
                        break; // stop and fail
                // shorten the resource in the last epoch if
                // seed_size extends beyond the last portion
                // of the resource
                if (e == epochs - 1 && resource_size % secret_size != 0) {
                        resource_size = resource_size % secret_size;
                }
                // write to storage out xor resource
                status = write_ctx_to_storage(fstr_output, fstr_resource, resource_size, out,
                                              secret_size, page_size);
        }

cleanup:
        // resource encrypted
        explicit_bzero(out, secret_size);
        free(out);
        return status;
}

void *run_inter(void *config) {
        inter_keymix_data *args = (inter_keymix_data *)config;
        int *err                = malloc(sizeof(int));
        if (err == NULL) {
                _log(LOG_DEBUG, "inter-keymix thread crashed at init time\n");
                goto thread_exit;
        }
        *err = 0;
        // mix-only (the coordinator applies the counter properly)
        *err = keymix(args->secret, args->out, args->seed_size, args->mixconfig, 1);
thread_exit:
        pthread_exit(err);
}

int keymix_inter_seq(struct arguments *config, FILE *fstr_output, FILE *fstr_resource,
                     size_t page_size, size_t resource_size, byte *secret, size_t secret_size) {

        int status = 0;

        // determine the numer of runs
        unsigned long runs = ceil(((double)resource_size) / (config->threads * secret_size));
        _log(LOG_DEBUG, "nof rounds %lu\n", runs);
        byte *out     = checked_malloc(secret_size * config->threads);
        byte *secrets = checked_malloc(secret_size * config->threads);
        // apply the iv once for all the threads
        memxor(secret, config->iv, SIZE_BLOCK);
        for (unsigned int t = 0; t < config->threads; t++) {
                memcpy(secrets + secret_size * t, secret, secret_size);
        }
        // set the mixing config
        mixing_config mix_conf = {config->mixfunc, config->diffusion};
        // prepare inter threads data
        inter_keymix_data args[config->threads];
        for (unsigned int t = 0; t < config->threads; t++) {
                args[t].out       = out + t * secret_size;
                args[t].secret    = secrets + t * secret_size;
                args[t].seed_size = secret_size;
                args[t].mixconfig = &mix_conf;
        }
        // mix with multiple rounds
        for (unsigned long r = 0; r < runs; r++) {
                //_log(LOG_DEBUG, "~~>run %ld\n", r);
                unsigned int real_nof_threads = config->threads;
                if (r == runs - 1) {
                        size_t runs_total_size = (r + 1) * config->threads * secret_size;
                        if (runs_total_size > resource_size) {
                                size_t last_chunk_size = resource_size;
                                if (r != 0) {
                                        last_chunk_size -= r * config->threads * secret_size;
                                }
                                real_nof_threads = ceil(((double)last_chunk_size) / secret_size);
                        }
                }
                _log(LOG_DEBUG, "real_nof_threads %u\n", real_nof_threads);
                // apply the correct counters
                unsigned int counter_clocks = config->threads;
                for (unsigned int t = 0; t < real_nof_threads; t++) {
                        if (r == 0) {
                                counter_clocks = t;
                        }
                        increment_counter(secrets + secret_size * t, counter_clocks);
                }
                // spawn the threads
                pthread_t threads[real_nof_threads];
                for (unsigned int t = 0; t < real_nof_threads; t++) {
                        status = pthread_create(&threads[t], NULL, run_inter, &args[t]);
                        if (status) {
                                _log(LOG_DEBUG, "pthread_create error %d\n", status);
                                goto cleanup;
                        }
                }
                // join the threads
                for (unsigned int t = 0; t < real_nof_threads; t++) {
                        status = pthread_join(threads[t], NULL);
                        // todo: use thread retval
                        if (status) {
                                _log(LOG_DEBUG, "pthread_join error %d (thread %d)\n", status, t);
                                goto cleanup;
                        }
                }
                // write to storage
                size_t writable_size = secret_size;
                for (unsigned int t = 0; t < real_nof_threads; t++) {
                        if (r == runs - 1 && t == real_nof_threads - 1 &&
                            resource_size % secret_size != 0) {
                                writable_size = resource_size % secret_size;
                        }
                        _log(LOG_DEBUG, "writable_size %lu\n", writable_size);
                        status = write_ctx_to_storage(fstr_output, fstr_resource, writable_size,
                                                      args[t].out, secret_size, page_size);
                }
        }
cleanup:
        explicit_bzero(out, secret_size * config->threads);
        free(out);
        explicit_bzero(secrets, secret_size * config->threads);
        free(secrets);
        return status;
}

int keymix_intra_seq(struct arguments *config, FILE *fstr_output, FILE *fstr_resource,
                     size_t page_size, size_t resource_size, byte *secret, size_t secret_size) {

        int status = 0;

        unsigned long epochs = (unsigned long)(ceil(((double)resource_size) / secret_size));
        if (config->verbose)
                printf("epochs:\t\t%ld\n", epochs);
        // set the mixing function
        mixing_config mix_conf = {config->mixfunc, config->diffusion};
        // prepare the memory
        byte *out = checked_malloc(secret_size);
        // apply the iv (16 bytes) to the first seed block
        memxor(secret, config->iv, SIZE_BLOCK);

        // mix T, T+1, ...
        for (unsigned long e = 0; e < epochs; e++) {
                _log(LOG_DEBUG, "~~>epoch %ld\n", e);
                // apply the counter
                if (e != 0)
                        increment_counter(secret, 1);
                status = keymix(secret, out, secret_size, &mix_conf, config->threads);
                if (status != 0)
                        break; // stop and fail
                // shorten the resource in the last epoch if
                // seed_size extends beyond the last portion
                // of the resource
                if (e == epochs - 1 && resource_size % secret_size != 0) {
                        resource_size = resource_size % secret_size;
                }
                // write to storage out xor resource
                status = write_ctx_to_storage(fstr_output, fstr_resource, resource_size, out,
                                              secret_size, page_size);
        }

cleanup:
        // resource encrypted
        explicit_bzero(out, secret_size);
        free(out);
        return status;
}

void *run_inter_intra(void *config) {
        inter_intra_keymix_data *args = (inter_intra_keymix_data *)config;
        int *err                      = malloc(sizeof(int));
        if (err == NULL) {
                _log(LOG_DEBUG, "inter-intra-keymix thread crashed at init time\n");
                goto thread_exit;
        }
        *err = 0;
        // mix-only (the coordinator applies the counter properly)
        *err = keymix(args->secret, args->out, args->seed_size, args->mixconfig, args->nof_threads);
thread_exit:
        pthread_exit(err);
}

int keymix_inter_intra_seq(struct arguments *config, FILE *fstr_output, FILE *fstr_resource,
                           size_t page_size, size_t resource_size, byte *secret,
                           size_t secret_size) {

        int status = 0;

        // thread groups
        unsigned int pow = config->diffusion;
        while (pow * config->diffusion <= config->threads)
                pow *= config->diffusion;
        unsigned int thread_groups = config->threads / pow;

        // determine the numer of runs
        unsigned long runs = ceil(((double)resource_size) / (thread_groups * secret_size));
        _log(LOG_DEBUG, "nof rounds %lu\n", runs);
        byte *out     = checked_malloc(secret_size * thread_groups);
        byte *secrets = checked_malloc(secret_size * thread_groups);
        // apply the iv once for all the threads
        memxor(secret, config->iv, SIZE_BLOCK);
        for (unsigned int t = 0; t < thread_groups; t++) {
                memcpy(secrets + secret_size * t, secret, secret_size);
        }
        // set the mixing config
        mixing_config mix_conf = {config->mixfunc, config->diffusion};
        // prepare inter threads data
        inter_intra_keymix_data args[thread_groups];
        for (unsigned int t = 0; t < thread_groups; t++) {
                args[t].out         = out + t * secret_size;
                args[t].secret      = secrets + t * secret_size;
                args[t].seed_size   = secret_size;
                args[t].mixconfig   = &mix_conf;
                args[t].nof_threads = pow;
        }
        // mix with multiple rounds
        for (unsigned long r = 0; r < runs; r++) {
                unsigned int real_nof_groups = thread_groups;
                if (r == runs - 1) {
                        size_t runs_total_size = (r + 1) * thread_groups * secret_size;
                        if (runs_total_size > resource_size) {
                                size_t last_chunk_size = resource_size;
                                if (r != 0) {
                                        last_chunk_size -= r * thread_groups * secret_size;
                                }
                                real_nof_groups = ceil(((double)last_chunk_size) / secret_size);
                        }
                }
                _log(LOG_DEBUG, "real_nof_groups %u\n", real_nof_groups);
                // apply the correct counters
                unsigned int counter_clocks = thread_groups;
                for (unsigned int t = 0; t < real_nof_groups; t++) {
                        if (r == 0) {
                                counter_clocks = t;
                        }
                        increment_counter(secrets + secret_size * t, counter_clocks);
                }
                // spawn the threads
                pthread_t threads[real_nof_groups];
                for (unsigned int t = 0; t < real_nof_groups; t++) {
                        status = pthread_create(&threads[t], NULL, run_inter_intra, &args[t]);
                        if (status) {
                                _log(LOG_DEBUG, "pthread_create error %d\n", status);
                                goto cleanup;
                        }
                }
                // join the threads
                for (unsigned int t = 0; t < real_nof_groups; t++) {
                        status = pthread_join(threads[t], NULL);
                        // todo: use thread retval
                        if (status) {
                                _log(LOG_DEBUG, "pthread_join error %d (thread %d)\n", status, t);
                                goto cleanup;
                        }
                }
                // write to storage
                size_t writable_size = secret_size;
                for (unsigned int t = 0; t < real_nof_groups; t++) {
                        if (r == runs - 1 && t == real_nof_groups - 1 &&
                            resource_size % secret_size != 0) {
                                writable_size = resource_size % secret_size;
                        }
                        _log(LOG_DEBUG, "writable_size %lu\n", writable_size);
                        status = write_ctx_to_storage(fstr_output, fstr_resource, writable_size,
                                                      args[t].out, secret_size, page_size);
                }
        }
cleanup:
        explicit_bzero(out, secret_size * thread_groups);
        free(out);
        explicit_bzero(secrets, secret_size * thread_groups);
        free(secrets);
        return status;
}
