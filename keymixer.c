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

const char *argp_program_version     = "keymixer 1.0";
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
    {"verbose", 'v', 0, 0, "Verbose mode", 7},
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

error_t parse_opt(int key, char *arg, struct argp_state *state) {
        cli_args_t *arguments = state->input;
        switch (key) {
        case ARGP_KEY_INIT:
                arguments->resource_path = NULL;
                arguments->output_path   = NULL;
                arguments->secret_path   = NULL;
                arguments->iv            = NULL;
                arguments->fanout        = 3;
                arguments->mixfunc       = MIXCTRPASS_WOLFSSL;
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
        case 'd':
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
        case ARGP_KEY_NO_ARGS:
                break;
        case ARGP_KEY_END:
                if (arguments->resource_path == NULL || arguments->output_path == NULL ||
                    arguments->secret_path == NULL || arguments->iv == NULL) {
                        ERROR_MSG(
                            "Missing arguments: resource, output, secret, and iv are mandatory\n");
                        goto arg_error;
                }
                break;
        case ARGP_KEY_FINI:
                break;
        case ARGP_KEY_SUCCESS:
                break;
        default:
                printf("Unrecognized input argument [%s] for key [%x]\n", arg, key);
                goto arg_error;
        }
        return 0;

arg_error:
        safe_explicit_bzero(arguments->iv, SIZE_BLOCK);
        free(arguments->iv);
        exit(ERR_ARGP);
}

int do_encrypt(cli_args_t *arguments, FILE *fstr_output, FILE *fstr_resource, FILE *fstr_secret) {

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
        encrypt_status = paged_storage_read(secret, fstr_secret, secret_size, page_size);
        if (encrypt_status != 0)
                goto cleanup;

        // determine the encryption mode
        int (*mixseqfunc)(cli_args_t *, FILE *, FILE *, size_t, size_t, byte *, size_t) = NULL;
        char *description                                                               = NULL;
        unsigned int pow = arguments->fanout;
        while (pow * arguments->fanout <= arguments->threads)
                pow *= arguments->fanout;
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

        cli_args_t cli_args;

        argp_parse(&argp, argc, argv, 0, 0, &cli_args);
        if (cli_args.verbose) {
                printf("===============\n");
                printf("KEYMIXER CONFIG\n");
                printf("===============\n");
                printf("resource: %s\n", cli_args.resource_path);
                printf("output:   %s\n", cli_args.output_path);
                printf("secret:   %s\n", cli_args.secret_path);
                printf("iv:       [redacted]\n");
                printf("aes impl: ");
                switch (cli_args.mixfunc) {
                case MIXCTRPASS_WOLFSSL:
                        printf("woflssl\n");
                        break;
                case MIXCTRPASS_OPENSSL:
                        printf("openssl\n");
                        break;
                case MIXCTRPASS_AESNI:
                        printf("aesni\n");
                        break;
                }
                printf("fanout:   %d\n", cli_args.fanout);
                printf("threads:  %d\n", cli_args.threads);
                printf("===============\n");
        }

        // prepare the streams
        FILE *fstr_resource = fopen(cli_args.resource_path, "r");
        if (fstr_resource == NULL) {
                ERROR_MSG("Cannot open resource file\n");
                prog_status = errno;
                goto close_fstr_resource;
        }
        // remove the previously encrypted resource if it exists
        FILE *fstr_output = fopen(cli_args.output_path, "r");
        if (fstr_output != NULL) {
                fclose(fstr_output);
                if (remove(cli_args.output_path) == 0) {
                        if (cli_args.verbose)
                                printf("Previous encrypted resource correctly removed\n");
                } else {
                        printf("(!) Unable to delete the previously encrypted resource\n");
                        prog_status = errno;
                        goto close_fstr_secret;
                }
        }
        fstr_output = fopen(cli_args.output_path, "w");
        if (fstr_output == NULL) {
                printf("(!) Cannot open create encrypted file file\n");
                prog_status = errno;
                goto close_fstr_output;
        }
        FILE *fstr_secret = fopen(cli_args.secret_path, "r");
        if (fstr_secret == NULL) {
                printf("(!) Cannot open secret file\n");
                prog_status = errno;
                goto close_fstr_secret;
        }
        // encrypt
        prog_status = do_encrypt(&cli_args, fstr_output, fstr_resource, fstr_secret);
close_fstr_secret:
        fclose(fstr_secret);
close_fstr_output:
        fclose(fstr_output);
close_fstr_resource:
        fclose(fstr_resource);
clean_arguments:
        explicit_bzero(cli_args.iv, SIZE_BLOCK);
        free(cli_args.iv);
        exit(prog_status);
}
