#include "file.h"
#include "mixctr.h"
#include "types.h"
#include "utils.h"
#include <argp.h>
#include <string.h>
#include <time.h>

#define ERROR_MSG(...) fprintf(stderr, __VA_ARGS__);

// ------------------------------------------------------------------ Option definitions

typedef struct {
        const char *input;
        char *output;
        const char *secret;
        uint128_t iv;
        unsigned int fanout;
        mixctr_t mixfunc;
        unsigned int threads;
        unsigned short verbose;
} cli_args_t;

enum args_key {
        ARG_KEY_OUTPUT  = 'o',
        ARG_KEY_SECRET  = 's',
        ARG_KEY_FANOUT  = 'f',
        ARG_KEY_LIBRARY = 'l',
        ARG_KEY_THREADS = 't',
        ARG_KEY_VERBOSE = 'v',
        ARG_KEY_IV      = 'i',
};

const char *argp_program_version     = "1.0.0";
const char *argp_program_bug_address = "<seclab@unibg.it>";
static char args_doc[]               = "INPUT";

// The order for an argp_opption is
// - long name
// - short name (if not zero)
// - argument name (if not NULL)
// - some flags, always zero for us
// - help description
// - the group the option is in, this is just a way to sort options alphabetically
//   in the same group (automatic options are put into group -1)
static struct argp_option options[] = {
    {"output", ARG_KEY_OUTPUT, "PATH", 0, "Output to file instead of standard output"},
    {"secret", ARG_KEY_SECRET, "PATH", 0, "Path of the secret"},
    {"iv", ARG_KEY_IV, "STRING", 0,
     "16-Byte initialization vector in hexadecimal format (default 0)"},
    {"fanout", ARG_KEY_FANOUT, "UINT", 0, "2, 3 (default), or 4"},
    {"library", ARG_KEY_LIBRARY, "STRING", 0, "wolfssl (default), openssl or aesni"},
    {"threads", ARG_KEY_THREADS, "UINT", 0, "Number of threads available (default 1)"},
    {"verbose", ARG_KEY_VERBOSE, NULL, 0, "Verbose mode"},
    {NULL}, // as per doc, this is necessary to terminate the options
};

error_t parse_opt(int, char *, struct argp_state *);

static struct argp argp = {options, parse_opt, args_doc,
                           "keymixer -- a cli program to encrypt resources using large secrets"};

// ------------------------------------------------------------------ Argument parsing

// I know about `strtol` and all the other stuff, but we need a 16-B unsigned
// integer, and `strtol` does a signed long :(
// Adapted from https://stackoverflow.com/questions/10156409/convert-hex-string-char-to-int
inline int hex2int(uint128_t *valp, char *hex) {
        // Work on a local copy (less pointer headaches is better)
        uint128_t val = *valp;
        while (*hex) {
                byte byte = tolower(*hex);
                // transform hex character to the 4bit equivalent number, using the ascii table
                // indexes
                if (byte >= '0' && byte <= '9')
                        byte = byte - '0';
                else if (byte >= 'a' && byte <= 'f')
                        byte = byte - 'a' + 10;
                else
                        return 1; // Invalid character detected

                // shift 4 to make space for new digit, and add the 4 bits of the new digit
                val = (val << 4) | (byte & 0xF);

                // go to next byte
                hex++;
        }
        // Everything is good, update the value
        *valp = val;
        return 0;
}
inline bool is_valid_fanout(int value) {
        return value == FANOUT2 || value == FANOUT3 || value == FANOUT4;
}

error_t parse_opt(int key, char *arg, struct argp_state *state) {
        cli_args_t *arguments = state->input;
        switch (key) {
        case ARG_KEY_OUTPUT:
                arguments->output = arg;
                break;
        case ARG_KEY_SECRET:
                arguments->secret = arg;
                break;
        case ARG_KEY_VERBOSE:
                arguments->verbose = true;
                break;
        case ARG_KEY_IV:
                if (strlen(arg) != 16) {
                        ERROR_MSG("Invalid IV: must be 16 Bytes\n");
                        return ERR_ARGP;
                }

                if (hex2int(&(arguments->iv), arg)) {
                        ERROR_MSG("Invalid IV: must consist of valid hex characters\n");
                        return ERR_ARGP;
                }
                break;
        case ARG_KEY_FANOUT:
                arguments->fanout = atoi(arg);
                if (!is_valid_fanout(arguments->fanout)) {
                        ERROR_MSG("Invalid fanout: must be 2, 3, or 4\n");
                        return ERR_ARGP;
                }
                break;
        case ARG_KEY_LIBRARY:
                arguments->mixfunc = mixctr_from_str(arg);
                if (arguments->mixfunc == -1) {
                        ERROR_MSG("Invalid library: must be wolfssl, openssl, or aesni\n");
                        return ERR_ARGP;
                }
                break;
        case ARG_KEY_THREADS:
                arguments->threads = strtoul(arg, NULL, 10);
                if (arguments->threads == 0) {
                        ERROR_MSG("Invalid threads: cannot be zero\n");
                        return ERR_ARGP;
                }
                break;
        case ARGP_KEY_ARG:
                // We accept only 1 input argument, the file
                if (state->arg_num > 0) {
                        // Too many arguments, note that argp_usage exits
                        argp_usage(state);
                }
                arguments->input = arg;
                break;
        case ARGP_KEY_END:
                if (state->arg_num < 1) {
                        // Too few arguments, note that argp_usage exits
                        argp_usage(state);
                }
                break;
        default:
                return ARGP_ERR_UNKNOWN;
        }

        return 0;
}

FILE *fopen_msg(const char *resource, char *mode) {
        FILE *fp = fopen(resource, mode);
        if (fp == NULL)
                ERROR_MSG("No such file: %s\n", resource);
        return fp;
};

int main(int argc, char **argv) {
        cli_args_t args;
        int err = 0;

        // Setup defaults
        args.input   = NULL;
        args.output  = NULL;
        args.secret  = NULL;
        args.iv      = 0;
        args.fanout  = 3;
        args.mixfunc = MIXCTR_WOLFSSL;
        args.threads = 1;
        args.verbose = false;
        args.output  = "-";

        // Start parsing
        if (argp_parse(&argp, argc, argv, 0, 0, &args))
                return EXIT_FAILURE;

        if (args.secret == NULL) {
                ERROR_MSG("Required argument: secret\n");
                return EXIT_FAILURE;
        }

        if (args.verbose) {
                printf("===============\n");
                printf("KEYMIXER CONFIG\n");
                printf("===============\n");
                printf("resource: %s\n", args.input);
                printf("output:   %s\n", args.output);
                printf("secret:   %s\n", args.secret);
                printf("iv:       [redacted]\n");
                // printf("%llx\n", (unsigned long long)(args.iv & 0xFFFFFFFFFFFFFFFF));
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
        FILE *fkey = fopen_msg(args.secret, "r");

        FILE *fout;
        if (strcmp(args.output, "-") == 0)
                fout = stdout;
        else
                fout = fopen_msg(args.output, "w");

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
        ctx_encrypt_init(&ctx, args.mixfunc, key, key_size, args.iv, args.fanout);

        // Do the encryption
        err = file_encrypt(fout, fin, &ctx, args.threads);

cleanup:
        safe_explicit_bzero(key, key_size);
        free(key);
        safe_fclose(fkey);
        safe_fclose(fout);
        safe_fclose(fin);
        return err;
}
