#include "file.h"
#include "mixctr.h"
#include "types.h"
#include "utils.h"
#include <argp.h>
#include <string.h>

#define ERROR_MSG(...) fprintf(stderr, __VA_ARGS__);

// ------------------------------------------------------------------ Option definitions

typedef struct {
        char *input;
        char *output;
        char *secret_path;
        byte *iv;
        unsigned int fanout;
        mixctr_t mixfunc;
        unsigned int threads;
        unsigned short verbose;
} cli_args_t;

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
    {"input", 'i', "PATH", 0, "Path of the resource to protect"},
    {"output", 'o', "PATH", 0, "Path of the output result"},
    {"secret", 's', "PATH", 0, "Path of the secret"},
    {"iv", 0, "STRING", 0, "16-Byte initialization vector (hexadecimal format)"},
    {"fanout", 'f', "UINT", 0, "Number of blocks per 384-bit macro (default is 3)"},
    {"library", 'l', "STRING", 0, "wolfssl (default), openssl or aesni"},
    {"threads", 't', "UINT", 0, "Number of threads available"},
    {"verbose", 'v', NULL, 0, "Verbose mode"},
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
                arguments->input       = NULL;
                arguments->output      = NULL;
                arguments->secret_path = NULL;
                arguments->iv          = NULL;
                arguments->fanout      = 3;
                arguments->mixfunc     = MIXCTR_WOLFSSL;
                arguments->threads     = 1;
                arguments->verbose     = 0;
                break;
        case 'r':
                arguments->input = arg;
                break;
        case 'o':
                arguments->output = arg;
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
                missing += check_missing(arguments->input, "input file");
                missing += check_missing(arguments->output, "output file");
                missing += check_missing(arguments->secret_path, "secret file");
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

int main(int argc, char **argv) {
        cli_args_t args;
        argp_parse(&argp, argc, argv, 0, 0, &args);

        if (args.verbose) {
                printf("===============\n");
                printf("KEYMIXER CONFIG\n");
                printf("===============\n");
                printf("resource: %s\n", args.input);
                printf("output:   %s\n", args.output);
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
        FILE *fin  = fopen_msg(args.input, "r");
        FILE *fout = fopen_msg(args.output, "w");
        FILE *fkey = fopen_msg(args.secret_path, "r");
        if (fin == NULL || fout == NULL || fkey == NULL)
                goto cleanup;

        // Read the key into memory
        size_t key_size = get_file_size(fkey);
        byte *key       = checked_malloc(key_size);

        if (key_size % SIZE_MACRO != 0) {
                ERROR_MSG("Wrong key size: must be a multiple of 48 B\n");
                goto cleanup;
        }

        size_t num_macros = key_size / SIZE_MACRO;
        if (!ISPOWEROF(num_macros, args.fanout)) {
                ERROR_MSG("Wrong key size: number of 48 B blocks is not a power of fanout\n");
                goto cleanup;
        }

        if (fread(key, key_size, 1, fkey) != 1)
                goto cleanup;

        // Setup the encryption context
        keymix_ctx_t ctx;
        ctx_encrypt_init(&ctx, args.mixfunc, key, key_size, *(uint128_t *)args.iv, args.fanout);

        // Do the encryption
        int err = file_encrypt(fout, fin, &ctx, args.threads);

cleanup:
        safe_explicit_bzero(key, key_size);
        free(key);
        safe_fclose(fkey);
        safe_fclose(fout);
        safe_fclose(fin);
        free(args.iv);
        return errno || err;
}
