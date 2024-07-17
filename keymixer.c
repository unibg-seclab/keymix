#include "aesni.h"
#include "config.h"
#include "keymix.h"
#include "keymix_t.h"
#include "openssl.h"
#include "types.h"
#include "utils.h"
#include "wolfssl.h"

#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/types.h>

const char *argp_program_version     = "keymixer 1.0";
const char *argp_program_bug_address = "<seclab@unibg.it>";
static char doc[] =
    "Keymixer -- a program to protect against partial exposure of the encryption key";
static char args_doc[] = ""; // no standard usage

static struct argp_option options[] = {
    {"secret", 's', "PATH", 0, "Path of the secret", 0},
    {"resource", 'r', "PATH", 0, "Path of the resource to protect", 1},
    {"iv", 'i', "IV", 0, "A 16-Byte initialization vector", 2},
    {"threads", 't', "UINT", 0, "Number of threads available", 3},
    {"diffusion", 'd', "UINT", 0, "Number of blocks per 384-bit macro (default is 3)", 4},
    {"verbose", 'v', 0, 0, "Verbose mode", 5},
    {0}};

struct arguments {
        char *secret_path;
        char *resource_path;
        byte *iv;
        unsigned int threads;
        unsigned int diff_factor;
        unsigned short verbose;
};

static void check_missing_arguments(struct argp_state *state) {
        struct arguments *arguments = state->input;
        if (arguments->secret_path == NULL || arguments->resource_path == NULL ||
            arguments->iv == NULL) {
                LOG("(!) Missing arguments -- SECRET, RESOURCE and IV are required\n");
                goto cleanup;
        }
        return;
cleanup:
        explicit_bzero(arguments->iv, SIZE_BLOCK);
        free(arguments->iv);
        exit(ERR_ARGP);
}

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
        struct arguments *arguments = state->input;
        switch (key) {
        case ARGP_KEY_INIT:
                /* initialize struct args */
                arguments->secret_path   = NULL;
                arguments->resource_path = NULL;
                arguments->iv            = NULL;
                arguments->threads       = 1;
                arguments->diff_factor   = 3;
                arguments->verbose       = 0;
                break;
        case 's':
                arguments->secret_path = arg;
                break;
        case 'r':
                arguments->resource_path = arg;
                break;
        case 'i':
                arguments->iv = checked_malloc(SIZE_BLOCK);
                if (strlen(arg) != SIZE_BLOCK) {
                        LOG("(!) A 16-Byte initialization vector is required\n");
                        goto cleanup;
                }
                for (int i = 0; i < SIZE_BLOCK; i++) {
                        *(arguments->iv + i) = (byte)(arg[i]);
                };
                break;
        case 't':
                arguments->threads = atoi(arg);
                if (arguments->threads < 1 || arguments->threads > 128) {
                        LOG("(!) Unsupported number of threads\n");
                        goto cleanup;
                }
                break;
        case 'd':
                arguments->diff_factor = atoi(arg);
                if (arguments->diff_factor < 2 || arguments->diff_factor > 4) {
                        LOG("(!) Invalid diffusion input, choose among 2, 3, 4\n");
                        goto cleanup;
                }
                break;
        case 'v':
                arguments->verbose = 1;
                break;
        case ARGP_KEY_NO_ARGS:
                break;
        case ARGP_KEY_END:
                check_missing_arguments(state);
                break;
        case ARGP_KEY_FINI:
                break;
        case ARGP_KEY_SUCCESS:
                break;
        default:
                printf("Unrecognized input argument [%s] for key [%x]\n", arg, key);
                goto cleanup;
        }
        return 0;
cleanup:
        explicit_bzero(arguments->iv, SIZE_BLOCK);
        free(arguments->iv);
        exit(ERR_ARGP);
}

static struct argp argp = {options, parse_opt, args_doc, doc};

int read_from_storage(byte *dst, FILE *fstr, size_t fstr_size, size_t page_size) {

        size_t nof_pages = fstr_size / page_size;
        size_t remainder = fstr_size % page_size;

        // read the pages
        for (; nof_pages > 0; nof_pages--) {
                if (1 != fread(dst, page_size, 1, fstr))
                        return ERR_FREAD;
        }
        // read the remainder (bytes)
        if (remainder != fread(dst, 1, remainder, fstr))
                return ERR_FREAD;

        return 0;
}

// Writes to fstr_encrypted the encrypted resource (out xor plaintext
// resource). The function can be simplified by reading and writing
// all the bytes with a single operation, however, that might fail on
// platforms where size_t is not large enough to store the size of
// min(resource_size, seed_size).  It seems there is no observable
// difference (in terms of performance) between using machine specific
// page-size vs reading the whole resource at once. mmap() as an
// alternative for fread() has been considered, again, apparently no
// particular performance difference on large seeds (more than
// 10MiB).
int write_enc_resource_to_storage(FILE *fstr_encrypted, FILE *fstr_resource, size_t resource_size,
                                  byte *out, size_t seed_size, size_t page_size) {

        int write_status = 0;

        size_t min_size  = MIN(resource_size, seed_size);
        size_t nof_pages = min_size / page_size;
        size_t remainder = min_size % page_size;

        // fwrite is slower than fread, so xor is done in memory using
        // a temporary buffer (in the future we can avoid reallocating
        // this buffer for every T, T+1, ...)
        byte *page    = checked_malloc(min_size);
        size_t offset = 0;
        for (; nof_pages > 0; nof_pages--) {
                // read the resource
                if (1 != fread(page, page_size, 1, fstr_resource)) {
                        write_status = ERR_FREAD;
                        goto clean_write;
                }
                // xor the resource with the mixed key
                memxor(out + offset, page, page_size);
                // write thre result to fstr_encrypted
                if (1 != fwrite(out + offset, page_size, 1, fstr_encrypted)) {
                        write_status = ERR_FWRITE;
                        goto clean_write;
                }
                offset += page_size;
        }
        // do the previous operations for the remainder of the
        // resource (when the tail is smaller than the seed_size)
        if (remainder != fread(page, 1, remainder, fstr_resource)) {
                write_status = ERR_FREAD;
                goto clean_write;
        }
        memxor(out, page, remainder);
        if (remainder != fwrite(out, 1, remainder, fstr_encrypted)) {
                write_status = ERR_FWRITE;
                goto clean_write;
        }

clean_write:
        explicit_bzero(page, page_size);
        free(page);
        return write_status;
}

int increment_counter(byte *macro) {
        byte carry           = 0x01;
        unsigned short start = 2 * SIZE_BLOCK - 1;
        while (start > 2 * SIZE_BLOCK - 9) {
                if (macro[start] == 0xff) {
                        macro[start] = 0x00;
                        start--;
                } else {
                        macro[start] += carry;
                        return 0;
                }
        }
        return ERR_RLIMIT;
}

int encrypt(struct arguments *arguments, FILE *fstr_encrypted, FILE *fstr_resource,
            FILE *fstr_secret) {

        // encrypt local config
        int encrypt_status    = 0;
        size_t size_threshold = 4 * SIZE_1MiB;

        // get the size of the secret and the resource
        size_t seed_size     = get_file_size(fstr_secret);
        size_t resource_size = get_file_size(fstr_resource);
        if (arguments->verbose) {
                printf("Resource size is %ld bytes, secret size is %ld bytes\n", resource_size,
                       seed_size);
        }

        // read the secret
        byte *secret   = checked_malloc(seed_size);
        int page_size  = getpagesize();
        encrypt_status = read_from_storage(secret, fstr_secret, seed_size, page_size);
        if (encrypt_status != 0)
                goto cleanup_bufs;

        // apply keymix
        if (arguments->threads == 1) { // use keymix
                if (arguments->verbose)
                        LOG("Using keymix (no parallelism)\n");
                // T, T+1, ...
                unsigned long epochs = (unsigned long)(ceil(((double)resource_size) / seed_size));
                if (arguments->verbose)
                        printf("epochs:\t\t%ld\n", epochs);
                // prepare the memory
                byte *out = checked_malloc(seed_size);
                // apply the iv (16 bytes) to the first seed block
                D print_buffer_hex(secret, SIZE_MACRO, "secret before iv");
                memxor(secret, arguments->iv, SIZE_BLOCK);
                D print_buffer_hex(secret, SIZE_MACRO, "secret after iv");
                // mix T, T+1, ...
                for (unsigned long e = 0; e < epochs; e++) {
                        D printf("~~>epoch %ld\n", e);
                        // apply the counter
                        encrypt_status = increment_counter(secret);
                        D print_buffer_hex(secret, SIZE_MACRO, "secret after ctr");
                        if (encrypt_status != 0)
                                break; // stop and fail
                        // todo: support other configs
                        mixing_config enc_conf = {&wolfssl, "wolf (128)", 3};
                        encrypt_status         = keymix(secret, out, seed_size, &enc_conf);
                        if (encrypt_status != 0)
                                break; // stop and fail
                        // xor out and resource, write the result to
                        // storage (shorten the last epoch if
                        // seed_size extends beyond the last portion
                        // of the resource)
                        if (e == epochs - 1 && resource_size % seed_size != 0) {
                                resource_size = resource_size % seed_size;
                        }
                        encrypt_status =
                            write_enc_resource_to_storage(fstr_encrypted, fstr_resource,
                                                          resource_size, out, seed_size, page_size);
                }
                // resource encrypted
                explicit_bzero(out, seed_size);
                free(out);
                goto cleanup_bufs;
        } else if (resource_size < size_threshold) {
                // use inter keymix
                // todo
        } else {
                // use a mix of intra and inter keymix based on the
                // number of thread available
                unsigned short encrypt_case = 0;
                unsigned int pow            = 1;
                while (pow * arguments->diff_factor <= arguments->threads)
                        pow *= arguments->diff_factor;
                if (pow == arguments->threads) {
                        // use only intra keymix
                        // todo
                } else {
                        // use many intra keymix with variable number of threads available
                        // todo
                }
        }

cleanup_bufs:
        explicit_bzero(secret, seed_size);
        free(secret);
ret:
        return encrypt_status;
}

int main(int argc, char **argv) {

        unsigned int prog_status = 0;
        // parse and check the arguments
        struct arguments arguments;
        argp_parse(&argp, argc, argv, 0, 0, &arguments);
        if (arguments.verbose) {
                printf("===============\n");
                printf("KEYMIXER CONFIG\n");
                printf("===============\n");
                printf("secret:\t\t%s\nresource:\t%s\niv:\t\t%s\nthreads:\t%d\ndiffusion:\t%d\n",
                       arguments.secret_path, arguments.resource_path, arguments.iv,
                       arguments.threads, arguments.diff_factor);
                printf("===============\n");
        }
        // prepare the streams
        FILE *fstr_resource = fopen(arguments.resource_path, "r");
        if (fstr_resource == NULL) {
                LOG("(!) Cannot open resource file\n");
                prog_status = errno;
                goto close_fstr_resource;
        }
        FILE *fstr_secret = fopen(arguments.secret_path, "r");
        if (fstr_secret == NULL) {
                LOG("(!) Cannot open secret file\n");
                prog_status = errno;
                goto close_fstr_secret;
        }
        // set the path of the new encrypted resource
        char suffix[] = ".enc";
        char *encrypted_path =
            (char *)checked_malloc(strlen(arguments.resource_path) + strlen(suffix) + 1);
        sprintf(encrypted_path, "%s%s", arguments.resource_path, suffix);
        if (arguments.verbose)
                printf("New resource encrypted at %s\n", encrypted_path);
        // remove the previously encrypted resource if it exists
        FILE *fstr_encrypted = fopen(encrypted_path, "r");
        if (fstr_encrypted != NULL) {
                fclose(fstr_encrypted);
                if (remove(encrypted_path) == 0) {
                        if (arguments.verbose)
                                LOG("Previous encrypted resource correctly removed\n");
                } else {
                        LOG("(!) Unable to delete the previously encrypted resource\n");
                        prog_status = errno;
                        goto close_fstr_secret;
                }
        }
        fstr_encrypted = fopen(encrypted_path, "w");
        if (fstr_encrypted == NULL) {
                LOG("(!) Cannot open create encrypted file file\n");
                prog_status = errno;
                goto close_fstr_encrypted;
        }
        // encrypt
        prog_status = encrypt(&arguments, fstr_encrypted, fstr_resource, fstr_secret);

clean_encrypted_path:
        free(encrypted_path);
close_fstr_encrypted:
        fclose(fstr_encrypted);
close_fstr_secret:
        fclose(fstr_secret);
close_fstr_resource:
        fclose(fstr_resource);
clean_arguments:
        explicit_bzero(arguments.iv, SIZE_BLOCK);
        free(arguments.iv);
        exit(prog_status);
}
