#include "enc.h"
#include "file.h"
#include "mixctr.h"
#include "types.h"
#include "utils.h"
#include <argp.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

void errmsg(const char *fmt, ...) {
        va_list args;
        va_start(args, fmt);
        fprintf(stderr, "keymixer: ");
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        va_end(args);
}

// ------------------------------------------------------------------ Option definitions

typedef struct {
        const char *input;
        const char *output;
        const char *key;
        uint128_t iv;
        unsigned int fanout;
        mixctr_t mixfunc;
        unsigned int threads;
        unsigned short verbose;
} cli_args_t;

enum args_key {
        ARG_KEY_OUTPUT  = 'o',
        ARG_KEY_FANOUT  = 'f',
        ARG_KEY_LIBRARY = 'l',
        ARG_KEY_THREADS = 't',
        ARG_KEY_VERBOSE = 'v',
        ARG_KEY_IV      = 'i',
};

const char *argp_program_version     = "1.0.0";
const char *argp_program_bug_address = "<seclab@unibg.it>";
static char args_doc[]               = "KEYFILE [INPUT]";

// The order for an argp_opption is
// - long name
// - short name (if not zero)
// - argument name (if not NULL)
// - some flags, always zero for us
// - help description
static struct argp_option options[] = {
    {"output", ARG_KEY_OUTPUT, "PATH", 0, "Output to file instead of standard output"},
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
                           "keymixer -- a cli program to encrypt resources using large keys"};

// ------------------------------------------------------------------ Argument parsing

// I know about `strtol` and all the other stuff, but we need a 16-B unsigned
// integer, and `strtol` does a signed long :(
// Adapted from https://stackoverflow.com/questions/10156409/convert-hex-string-char-to-int
inline int hex2int(uint128_t *valp, char *hex) {
        // Work on a local copy (less pointer headaches is better)
        uint128_t val = 0;
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
inline int strtofanout(fanout_t *out, char *str) {
        int x = atoi(str);
        switch (x) {
        case FANOUT2:
        case FANOUT3:
        case FANOUT4:
                *out = x;
                return 0;
        default:
                return 1;
        }
}

error_t parse_opt(int key, char *arg, struct argp_state *state) {
        cli_args_t *arguments = state->input;
        switch (key) {
        case ARG_KEY_OUTPUT:
                arguments->output = arg;
                break;
        case ARG_KEY_VERBOSE:
                arguments->verbose = true;
                break;
        case ARG_KEY_IV:
                if (strlen(arg) != 16)
                        argp_error(state, "IV must be 16-B long");
                if (hex2int(&(arguments->iv), arg))
                        argp_error(state, "IV must consist of valid hex characters");
                break;
        case ARG_KEY_FANOUT:
                if (strtofanout(&(arguments->fanout), arg))
                        argp_error(state, "fanout must be one of %d, %d, %d", FANOUT2, FANOUT3,
                                   FANOUT4);
                break;
        case ARG_KEY_LIBRARY:
                arguments->mixfunc = mixctr_from_str(arg);
                if (arguments->mixfunc == -1)
                        argp_error(state, "library must be one of wolfssl, openssl, aesni");
                break;
        case ARG_KEY_THREADS:
                arguments->threads = strtoul(arg, NULL, 10);
                if (arguments->threads == 0)
                        argp_error(state, "threads must be a positive number");
                break;
        case ARGP_KEY_ARG:
                // We accept only 2 input argument, the key and (possibly) the file
                if (state->arg_num == 0)
                        arguments->key = arg;
                else if (state->arg_num == 1)
                        arguments->input = arg;
                else
                        // Too many arguments, note that argp_usage exits
                        argp_usage(state);
                break;
        case ARGP_KEY_END:
                if (state->arg_num < 1)
                        // Too few arguments, note that argp_usage exits
                        argp_usage(state);
                break;
        default:
                return ARGP_ERR_UNKNOWN;
        }

        return 0;
}

FILE *fopen_msg(const char *resource, char *mode) {
        FILE *fp = fopen(resource, mode);
        if (fp == NULL)
                errmsg("no such file '%s'", resource);
        return fp;
};

int main(int argc, char **argv) {
        cli_args_t args;
        int err = 0;

        // Setup defaults
        args.input   = NULL;
        args.output  = NULL;
        args.key     = NULL;
        args.iv      = 0;
        args.fanout  = 3;
        args.mixfunc = MIXCTR_WOLFSSL;
        args.threads = 1;
        args.verbose = false;

        // Start parsing
        if (argp_parse(&argp, argc, argv, 0, 0, &args))
                return EXIT_FAILURE;

        if (args.verbose) {
                printf("===============\n");
                printf("KEYMIXER CONFIG\n");
                printf("===============\n");
                printf("resource: %s\n", args.input);
                printf("output:   %s\n", args.output);
                printf("key:      %s\n", args.key);
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

        // Setup variables here, before the gotos start
        size_t key_size = 0;
        byte *key       = NULL;

        // prepare the streams
        FILE *fkey = fopen_msg(args.key, "r");

        FILE *fin = stdin;
        if (args.input != NULL)
                fin = fopen_msg(args.input, "r");

        FILE *fout = stdout;
        if (args.output != NULL)
                fout = fopen_msg(args.output, "w");

        if (fin == NULL || fout == NULL || fkey == NULL) {
                err = EXIT_FAILURE;
                goto cleanup;
        }

        // Read the key into memory
        key_size = get_file_size(fkey);
        key      = checked_malloc(key_size);

        if (key_size % SIZE_MACRO != 0) {
                errmsg("key must be a multiple of %d B", SIZE_MACRO);
                goto cleanup;
        }

        size_t num_macros = key_size / SIZE_MACRO;
        if (!ISPOWEROF(num_macros, args.fanout)) {
                errmsg("key;s number of 48-B blocks is not a power of fanout (%d)", args.fanout);
                goto cleanup;
        }

        if (fread(key, key_size, 1, fkey) != 1)
                goto cleanup;

        // Do the encryption
        keymix_ctx_t ctx;
        ctx_encrypt_init(&ctx, args.mixfunc, key, key_size, args.iv, args.fanout);
        err = stream_encrypt(fout, fin, &ctx, args.threads);

        // ctx_keymix_init(&ctx, args.mixfunc, key, key_size, args.fanout);
        // ctx_enable_iv_counter(&ctx, args.iv);
        // err = stream_encrypt2(fout, fin, &ctx, args.threads);

cleanup:
        safe_explicit_bzero(key, key_size);
        free(key);
        safe_fclose(fkey);
        if (args.input != NULL)
                safe_fclose(fin);
        if (args.output != NULL)
                safe_fclose(fout);
        return err;
}
