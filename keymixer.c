#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "aesni.h"
#include "config.h"
#include "keymix_seq.h"
#include "log.h"
#include "openssl.h"
#include "types.h"
#include "utils.h"
#include "wolfssl.h"

const char *argp_program_version     = "keymixer 1.0";
const char *argp_program_bug_address = "<seclab@unibg.it>";
static char doc[]      = "keymixer -- a cli program to encrypt resources using large secrets";
static char args_doc[] = ""; // no need to print a standard usage

static struct argp_option options[] = {
    {"resource", 'r', "PATH", 0, "Path of the resource to protect", 0},
    {"output", 'o', "PATH", 0, "Path of the output result", 1},
    {"secret", 's', "PATH", 0, "Path of the secret", 2},
    {"iv", 'i', "STRING", 0, "16-Byte initialization vector (hexadecimal format)", 3},
    {"diffusion", 'd', "UINT", 0, "Number of blocks per 384-bit macro (default is 3)", 4},
    {"library", 'l', "STRING", 0, "wolfssl (default), openssl or aesni", 5},
    {"threads", 't', "UINT", 0, "Number of threads available", 6},
    {"verbose", 'v', 0, 0, "Verbose mode", 7},
    {0}};

static void check_missing_arguments(struct argp_state *state) {
        struct arguments *arguments = state->input;
        if (arguments->resource_path == NULL || arguments->output_path == NULL ||
            arguments->secret_path == NULL || arguments->iv == NULL) {
                printf("(!) Missing arguments -- resource, output, secret and iv are mandatory\n");
                goto cleanup;
        }
        return;
cleanup:
        if (arguments->iv != NULL) {
                explicit_bzero(arguments->iv, SIZE_BLOCK);
                free(arguments->iv);
        }
        exit(ERR_ARGP);
}

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
        struct arguments *arguments = state->input;
        switch (key) {
        case ARGP_KEY_INIT:
                /* initialize struct args */
                arguments->resource_path = NULL;
                arguments->output_path   = NULL;
                arguments->secret_path   = NULL;
                arguments->iv            = NULL;
                arguments->diffusion     = 3;
                arguments->mixfunc       = &wolfssl;
                arguments->threads       = 1;
                arguments->verbose       = 0;
                arguments->mixfunc_descr = "wolfssl";
                break;
        case 'r':
                arguments->resource_path = arg;
                break;
        case 'o':
                arguments->output_path = arg;
                break;
        case 's':
                arguments->secret_path = arg;
                break;
        case 'i':
                arguments->iv = checked_malloc(SIZE_BLOCK);
                if (strlen(arg) != SIZE_BLOCK) {
                        printf("(!) A 16-Byte initialization vector is required\n");
                        goto cleanup;
                }
                char dict[16] = "0123456789abcdef";
                int hex_found;
                for (int i = 0; i < SIZE_BLOCK; i++) {
                        hex_found = 0;
                        for (int j = 0; j < 16; j++)
                                if (arg[i] == dict[i]) {
                                        hex_found = 1;
                                        break;
                                }
                        if (hex_found == 0) {
                                printf("(!) Unrecognized hex symbol found in iv\n");
                                goto cleanup;
                        }
                        *(arguments->iv + i) = (byte)(arg[i]);
                };
                break;
        case 'd':
                arguments->diffusion   = atoi(arg);
                unsigned int values[3] = {2, 3, 4};
                int diff_found         = 0;
                for (unsigned int i = 0; i < sizeof(values) / sizeof(unsigned int); i++)
                        if (arguments->diffusion == values[i]) {
                                diff_found = 1;
                                break;
                        }
                if (diff_found == 0) {
                        _log(LOG_INFO, "(!) Invalid DIFFUSION input -- choose among 2, 3, 4\n");
                        goto cleanup;
                }
                break;
        case 'l':
                if (strcmp(arg, "wolfssl") == 0) {
                        arguments->mixfunc       = &wolfssl;
                        arguments->mixfunc_descr = "wolfssl";
                } else if (strcmp(arg, "openssl") == 0) {
                        arguments->mixfunc       = &openssl;
                        arguments->mixfunc_descr = "openssl";
                } else if (strcmp(arg, "aesni") == 0) {
                        arguments->mixfunc       = &aesni;
                        arguments->mixfunc_descr = "aesni";
                } else {
                        _log(LOG_INFO,
                             "(!) Invalid LIBRARY -- choose among wolfssl, openssl, aesni\n");
                        goto cleanup;
                }
                break;
        case 't':
                arguments->threads = atoi(arg);
                if (arguments->threads < 1 || arguments->threads > 128) {
                        _log(LOG_INFO, "(!) Unsupported number of threads\n");
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
        if (arguments->iv != NULL) {
                explicit_bzero(arguments->iv, SIZE_BLOCK);
                free(arguments->iv);
        }
        exit(ERR_ARGP);
}

static struct argp argp = {options, parse_opt, args_doc, doc};

int storage_read(byte *dst, FILE *fstr, size_t fstr_size, size_t page_size) {

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

// Writes to fstr_output the encrypted resource. The function can be
// simplified by reading and writing all the bytes with a single
// operation, however, that might fail on platforms where size_t is
// not large enough to store the size of min(resource_size,
// seed_size).  It seems there is no observable difference (in terms
// of performance) between using machine specific page-size vs reading
// the whole resource at once. mmap() as an alternative for fread()
// has been considered, again, apparently no particular performance
// difference for seeds larger than 10MiB.
int storage_write(FILE *fstr_output, FILE *fstr_resource, size_t resource_size, byte *out,
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

int encrypt(struct arguments *arguments, FILE *fstr_output, FILE *fstr_resource,
            FILE *fstr_secret) {

        // encrypt local config
        int encrypt_status    = 0;
        size_t size_threshold = SIZE_1MiB;

        // get the size of the secret and the resource
        size_t secret_size   = get_file_size(fstr_secret);
        size_t resource_size = get_file_size(fstr_resource);
        if (arguments->verbose) {
                printf("Resource size is %ld bytes, secret size is %ld bytes\n", resource_size,
                       secret_size);
        }

        // get the size of storage pages
        int page_size = getpagesize();

        // read the secret
        byte *secret   = checked_malloc(secret_size);
        encrypt_status = storage_read(secret, fstr_secret, secret_size, page_size);
        if (encrypt_status != 0)
                goto cleanup;

        // determine the encryption mode
        int (*mixseqfunc)(struct arguments *, FILE *, FILE *, size_t, size_t, byte *, size_t) =
            NULL;
        char *description = NULL;
        unsigned int pow  = arguments->diffusion;
        while (pow * arguments->diffusion <= arguments->threads)
                pow *= arguments->diffusion;
        if (arguments->threads == 1) {
                // 1 core -> single-threaded
                mixseqfunc  = &keymix_seq;
                description = "Encrypting with single-core keymix";
        } else if (secret_size < size_threshold) {
                // small seed + many threads -> inter-keymix
                mixseqfunc  = &keymix_inter_seq;
                description = "Encrypting with inter-keymix";
        } else if (arguments->threads % pow != 0) {
                // large seed + unbalanced number of threads -> inter-mix
                mixseqfunc  = &keymix_inter_seq;
                description = "Encrypting with inter-keymix";
        } else if (arguments->threads == pow) {
                //  large seed + power nof threads -> intra-keymix
                mixseqfunc  = &keymix_intra_seq;
                description = "Encrypting with intra-keymix";
        } else if (arguments->threads % pow == 0) {
                // large seed + multiple of power nof threads -> inter & intra-keymix
                mixseqfunc  = &keymix_inter_intra_seq;
                description = "Encrypting with inter-intra-keymix";
        }

        // keymix
        if (mixseqfunc == NULL) {
                printf("No suitable encryption mode found\n");
                encrypt_status = ERR_MODE;
                goto cleanup;
        }
        if (arguments->verbose)
                printf("%s\n", description);
        encrypt_status = (*(mixseqfunc))(arguments, fstr_output, fstr_resource, page_size,
                                         resource_size, secret, secret_size);
        if (encrypt_status != 0)
                goto cleanup;

cleanup:
        explicit_bzero(secret, secret_size);
        free(secret);
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
                printf("resource:\t%s\noutput:\t\t%s\nsecret:\t\t%s\n", arguments.resource_path,
                       arguments.output_path, arguments.secret_path);
                printf("iv:\t\t%s\ndiffusion:\t%d\nlibrary:\t%s\nthreads:\t%d\n", arguments.iv,
                       arguments.diffusion, arguments.mixfunc_descr, arguments.threads);
                printf("===============\n");
        }
        // prepare the streams
        FILE *fstr_resource = fopen(arguments.resource_path, "r");
        if (fstr_resource == NULL) {
                printf("(!) Cannot open resource file\n");
                prog_status = errno;
                goto close_fstr_resource;
        }
        // remove the previously encrypted resource if it exists
        FILE *fstr_output = fopen(arguments.output_path, "r");
        if (fstr_output != NULL) {
                fclose(fstr_output);
                if (remove(arguments.output_path) == 0) {
                        if (arguments.verbose)
                                printf("Previous encrypted resource correctly removed\n");
                } else {
                        printf("(!) Unable to delete the previously encrypted resource\n");
                        prog_status = errno;
                        goto close_fstr_secret;
                }
        }
        fstr_output = fopen(arguments.output_path, "w");
        if (fstr_output == NULL) {
                printf("(!) Cannot open create encrypted file file\n");
                prog_status = errno;
                goto close_fstr_output;
        }
        FILE *fstr_secret = fopen(arguments.secret_path, "r");
        if (fstr_secret == NULL) {
                printf("(!) Cannot open secret file\n");
                prog_status = errno;
                goto close_fstr_secret;
        }
        // encrypt
        prog_status = encrypt(&arguments, fstr_output, fstr_resource, fstr_secret);
close_fstr_secret:
        fclose(fstr_secret);
close_fstr_output:
        fclose(fstr_output);
close_fstr_resource:
        fclose(fstr_resource);
clean_arguments:
        explicit_bzero(arguments.iv, SIZE_BLOCK);
        free(arguments.iv);
        exit(prog_status);
}
