#include "config.h"
#include "file.h"
#include "keymix_seq.h"
#include "mixctr.h"
#include "types.h"
#include "utils.h"
#include <argp.h>
#include <string.h>
#include <unistd.h>

#define ERROR_MSG(...) fprintf(stderr, __VA_ARGS__);

// ------------------------------------------------------------------ Option definitions

const char *argp_program_version     = "1.0.0";
const char *argp_program_bug_address = "<seclab@unibg.it>";

// The order for an argp_opption is
// - long name
// - short name (if not zero)
// - argument name (if not NULL)
// - some flags, always zero for us
// - help description
// - the group the option is in, this is just a way to sort options alphabetically
//   in the same group (automatic options are put into group -1)
static struct argp_option options[] = {
    {"resource", 'r', "PATH", 0, "Path of the resource to protect", 0},
    {"output", 'o', "PATH", 0, "Path of the output result", 1},
    {"secret", 's', "PATH", 0, "Path of the secret", 2},
    {"iv", 'i', "STRING", 0, "16-Byte initialization vector (hexadecimal format)", 3},
    {"fanout", 'f', "UINT", 0, "Number of blocks per 384-bit macro (default is 3)", 4},
    {"library", 'l', "STRING", 0, "wolfssl (default), openssl or aesni", 5},
    {"threads", 't', "UINT", 0, "Number of threads available", 6},
    {"verbose", 'v', NULL, 0, "Verbose mode", 7},
    {NULL}, // as per doc, this is necessary to terminate the options
};

error_t parse_opt(int, char *, struct argp_state *);

static struct argp argp = {options, parse_opt, "",
                           "keymixer -- a cli program to encrypt resources using large secrets"};

// ------------------------------------------------------------------ Argument parsing

inline bool is_hex_value(char c) {
        c = tolower(c);
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

inline bool is_valid_fanout(int value) {
        return value == FANOUT2 || value == FANOUT3 || value == FANOUT4;
}

inline int check_missing(void *arg, char *name) {
        if (arg == NULL) {
                fprintf(stderr, "Argument required: %s\n", name);
                return 1;
        }
        return 0;
}

error_t parse_opt(int key, char *arg, struct argp_state *state) {
        cli_args_t *arguments = state->input;
        int missing           = 0;
        switch (key) {
        case ARGP_KEY_INIT:
                arguments->resource_path = NULL;
                arguments->output_path   = NULL;
                arguments->secret_path   = NULL;
                arguments->iv            = NULL;
                arguments->fanout        = 3;
                arguments->mixfunc       = MIXCTR_WOLFSSL;
                arguments->threads       = 1;
                arguments->verbose       = 0;
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
                size_t len    = strlen(arg);
                if (len != SIZE_BLOCK) {
                        ERROR_MSG("A 16-Byte initialization vector is required\n");
                        goto arg_error;
                }

                for (int i = 0; i < len; i++) {
                        if (is_hex_value(arg[i])) {
                                arguments->iv[i] = (byte)arg[i];
                        } else {
                                ERROR_MSG(
                                    "Unrecognized symbol in IV: must be a valid hex symbol\n");
                                goto arg_error;
                        }
                }
                break;
        case 'f':
                arguments->fanout = atoi(arg);
                if (!is_valid_fanout(arguments->fanout)) {
                        ERROR_MSG("Invalid fanout, valid values are 2, 3, or 4\n");
                        goto arg_error;
                }
                break;
        case 'l':
                arguments->mixfunc = mixctr_from_str(arg);
                if (arguments->mixfunc == -1) {
                        ERROR_MSG("Invalid LIBRARY -- choose among wolfssl, openssl, aesni\n");
                        goto arg_error;
                }
                break;
        case 't':
                arguments->threads = atoi(arg);
                if (arguments->threads < 1 || arguments->threads > 128) {
                        ERROR_MSG("Unsupported number of threads, at least 1 and at most 128\n");
                        goto arg_error;
                }
                break;
        case 'v':
                arguments->verbose = 1;
                break;
        case ARGP_KEY_END:
                missing = 0;
                missing += check_missing(arguments->resource_path, "resource");
                missing += check_missing(arguments->output_path, "output");
                missing += check_missing(arguments->secret_path, "secret");
                missing += check_missing(arguments->iv, "iv");
                if (missing > 0)
                        goto arg_error;
                break;
        case ARGP_KEY_FINI:
        case ARGP_KEY_NO_ARGS:
        case ARGP_KEY_SUCCESS:
                break;
        default:
                ERROR_MSG("Unrecognized input argument [%s] for key [%x]\n", arg, key);
                goto arg_error;
        }
        return 0;

arg_error:
        safe_explicit_bzero(arguments->iv, SIZE_BLOCK);
        free(arguments->iv);
        exit(ERR_ARGP);
}

FILE *fopen_msg(char *resource, char *mode) {
        FILE *fp = fopen(resource, mode);
        if (!fp)
                ERROR_MSG("No such file: %s\n", resource);
        return fp;
};

void safe_fclose(FILE *fp) {
        if (fp)
                fclose(fp);
}

int main(int argc, char **argv) {
        cli_args_t args;
        argp_parse(&argp, argc, argv, 0, 0, &args);

        if (args.verbose) {
                printf("===============\n");
                printf("KEYMIXER CONFIG\n");
                printf("===============\n");
                printf("resource: %s\n", args.resource_path);
                printf("output:   %s\n", args.output_path);
                printf("secret:   %s\n", args.secret_path);
                printf("iv:       [redacted]\n");
                printf("aes impl: ");
                switch (args.mixfunc) {
                case MIXCTR_WOLFSSL:
                        printf("woflssl\n");
                        break;
                case MIXCTR_OPENSSL:
                        printf("openssl\n");
                        break;
                case MIXCTR_AESNI:
                        printf("aesni\n");
                        break;
                }
                printf("fanout:   %d\n", args.fanout);
                printf("threads:  %d\n", args.threads);
                printf("===============\n");
        }

        // prepare the streams
        FILE *fin  = fopen_msg(args.resource_path, "r");
        FILE *fout = fopen_msg(args.output_path, "w");
        FILE *fkey = fopen_msg(args.secret_path, "r");
        if (fin == NULL || fout == NULL || fkey == NULL)
                goto cleanup;

        int err               = 0;
        size_t size_threshold = SIZE_1MiB;

        // get the size of the secret and the resource
        size_t secret_size   = get_file_size(fkey);
        size_t resource_size = get_file_size(fin);
        if (args.verbose) {
                printf("Resource size is %ld bytes, secret size is %ld bytes\n", resource_size,
                       secret_size);
        }

        // read the secret
        byte *secret = checked_malloc(secret_size);
        size_t read  = fread(secret, secret_size, 1, fkey);
        if (read != 1)
                goto cleanup;

        // determine the encryption mode
        int (*mixseqfunc)(cli_args_t *, FILE *, FILE *, size_t, size_t, byte *, size_t) = NULL;

        uint8_t internal_threads = 1;
        uint8_t external_threads = 1;

        if (args.threads == 1) {
                mixseqfunc = &keymix_seq;
                if (args.verbose)
                        printf("Encrypting with single-core keymix\n");
        } else if (ISPOWEROF(args.threads, args.fanout)) {
                internal_threads = args.threads;
                external_threads = 1;
                mixseqfunc       = &keymix_intra_seq;
                if (args.verbose)
                        printf("Encrypting with intra-keymix\n");
        } else if (args.threads % args.fanout == 0) {
                // Find highest power of fanout and use that as the internal threads,
                // and the external threads will be the remaining.
                // In this way, we always guarantee that we use at most the
                // number of threads chosen by the user.
                internal_threads = args.fanout;
                while (internal_threads * args.fanout <= args.threads)
                        internal_threads *= args.fanout;

                external_threads = args.threads - internal_threads;
                mixseqfunc       = &keymix_inter_intra_seq;
                if (args.verbose)
                        printf("Encrypting with inter-intra-keymix\n");
        } else {
                internal_threads = 1;
                external_threads = args.threads;
                mixseqfunc       = &keymix_inter_seq;
                if (args.verbose)
                        printf("Encrypting with inter-keymix\n");
        }

        // keymix
        if (mixseqfunc == NULL) {
                ERROR_MSG("No suitable encryption mode found\n");
                err = ERR_MODE;
                goto cleanup;
        }
        err = (*(mixseqfunc))(&args, fout, fin, getpagesize(), resource_size, secret, secret_size);
        if (err)
                goto cleanup;

cleanup:
        explicit_bzero(secret, secret_size);
        free(secret);
        if (fkey)
                fclose(fkey);
        if (fout)
                fclose(fout);
        if (fin)
                fclose(fin);
        safe_explicit_bzero(args.iv, SIZE_BLOCK);
        free(args.iv);
        return errno || err;
}
