#include <argp.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "ctx.h"
#include "file.h"
#include "keymix.h"
#include "types.h"
#include "utils.h"

// ------------------------------------------------------------------ Error management and codes

#define ERR_ENC 100
#define ERR_KEY_SIZE 101
#define ERR_KEY_READ 102
#define ERR_UNKNOWN_MIX 103
#define ERR_MISSING_MIX 104
#define ERR_UNKNOWN_ONE_WAY_MIX 105
#define ERR_MISSING_ONE_WAY_MIX 106
#define ERR_NOT_ONE_WAY 107
#define ERR_INCOMPATIBLE_PRIMITIVES 108
#define ERR_EQUAL_PRIMITIVES 109

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
        byte iv[KEYMIX_IV_SIZE];
        uint8_t fanout;
        enc_mode_t enc_mode;
        mix_impl_t mix;
        mix_impl_t one_way_mix;
        uint8_t threads;
        bool verbose;
} cli_args_t;

enum args_key {
        ARG_KEY_ENC_MODE          = 'e',
        ARG_KEY_IV                = 'i',
        ARG_KEY_ONE_WAY_PRIMITIVE = 0x100,
        ARG_KEY_OUTPUT            = 'o',
        ARG_KEY_PRIMITIVE         = 'p',
        ARG_KEY_THREADS           = 't',
        ARG_KEY_VERBOSE           = 'v',
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
    {"enc-mode", ARG_KEY_ENC_MODE, "STRING", 0, "Encryption mode (default: ctr)"},
    {"iv", ARG_KEY_IV, "STRING", 0,
     "16-Byte initialization vector in hexadecimal format (default: 0)"},
    {"one-way-primitive", ARG_KEY_ONE_WAY_PRIMITIVE, "STRING", 0,
     "One of the mixing primitive available (default: none)"},
    {"output", ARG_KEY_OUTPUT, "PATH", 0, "Output to file instead of standard output"},
    {"primitive", ARG_KEY_PRIMITIVE, "STRING", 0,
     "One of the mixing primitive available (default: xkcp-tuboshake-128)"},
    {"threads", ARG_KEY_THREADS, "UINT", 0, "Number of threads"},
    {"verbose", ARG_KEY_VERBOSE, NULL, 0, "Verbose mode"},
    {NULL}, // as per doc, this is necessary to terminate the options
};

error_t parse_opt(int, char *, struct argp_state *);

static struct argp argp = {options, parse_opt, args_doc,
                           "keymixer -- a cli program to encrypt resources using large keys"};

// ------------------------------------------------------------------ Argument parsing

inline int parse_hex(byte *bytes, size_t len, char *hex) {
        for (int i = 0; *hex && i < len; i++) {
                if (sscanf(hex + 2*i, "%2hhx", bytes + i) <= 0) {
                        return 1;
                }
        }
        return 0;
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
                if (strlen(arg) != 2 * KEYMIX_IV_SIZE)
                        argp_error(state, "IV must be %d-B long", KEYMIX_IV_SIZE);
                if (parse_hex(arguments->iv, KEYMIX_IV_SIZE,  arg))
                        argp_error(state, "IV must consist of valid hex characters");
                break;
        case ARG_KEY_ENC_MODE:
                arguments->enc_mode = get_enc_mode_type(arg);
                if (arguments->enc_mode == -1)
                        argp_error(state, "encryption mode must be one of ctr, ctr-opt, ofb");
                break;
        case ARG_KEY_PRIMITIVE:
                arguments->mix = get_mix_type(arg);
                if (arguments->mix == -1)
                        argp_error(state, "primitive must be one of the available ones");
                break;
        case ARG_KEY_ONE_WAY_PRIMITIVE:
                arguments->one_way_mix = get_mix_type(arg);
                if (arguments->one_way_mix == -1)
                        argp_error(state, "one-way primitive must be one of the available ones");
                break;
        case ARG_KEY_THREADS:
                long value = strtol(arg, NULL, 10);
                if (value <= 0)
                        argp_error(state, "number of threads must be at least 1");
                arguments->threads = value;
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

int checked_fopen(FILE **fp, const char *resource, char *mode, FILE *default_fp) {
        *fp = default_fp;
        if (resource != NULL) {
                *fp = fopen(resource, mode);
                if (*fp == NULL) {
                        errmsg("no such file '%s'", resource);
                        return ENOENT;
                }
        }
        return 0;
};

int main(int argc, char **argv) {
        int err = 0;

        // Setup defaults
        cli_args_t args = {
            .input       = NULL,
            .output      = NULL,
            .key         = NULL,
            .iv          = 0,
            .enc_mode    = ENC_MODE_CTR,
            .mix         = XKCP_TURBOSHAKE_128,
            .one_way_mix = NONE,
            .threads     = 1,
            .verbose     = false,
        };

        // Start parsing
        if (argp_parse(&argp, argc, argv, 0, 0, &args))
                return EXIT_FAILURE;

        // Setup fanout
        get_fanouts_from_mix_type(args.mix, 1, (uint8_t *)&args.fanout);

        if (args.verbose) {
                printf("===============\n");
                printf("KEYMIXER CONFIG\n");
                printf("===============\n");
                printf("resource:          %s\n", args.input);
                printf("output:            %s\n", args.output);
                printf("key:               %s\n", args.key);
                printf("iv:                [redacted]\n");
                // printf("%llx\n", (unsigned long long)(args.iv & 0xFFFFFFFFFFFFFFFF));
                printf("enc mode:          %s", get_enc_mode_name(args.enc_mode));
                printf("primitive:         %s", get_mix_name(args.mix));
                printf("one-way primitive: %s", get_mix_name(args.one_way_mix));
                printf("fanout:            %d\n", args.fanout);
                printf("threads:           %d\n", args.threads);
                printf("===============\n");
        }

        // Setup variables here, before the gotos start
        size_t key_size = 0;
        byte *key       = NULL;

        // Prepare the streams
        FILE *fkey = NULL;
        FILE *fin  = NULL;
        FILE *fout = NULL;

        err = checked_fopen(&fkey, args.key, "r", NULL);
        if (err)
                goto cleanup;

        err = checked_fopen(&fin, args.input, "r", stdin);
        if (err)
                goto cleanup;

        err = checked_fopen(&fout, args.output, "w", stdout);
        if (err)
                goto cleanup;

        // Read the key into memory
        key_size = get_file_size(fkey);
        key      = checked_malloc(key_size);

        if (fread(key, 1, key_size, fkey) != key_size) {
                err = ERR_KEY_READ;
                goto cleanup;
        }

        // Do the encryption
        ctx_t ctx;
        err = ctx_encrypt_init(&ctx, args.enc_mode, args.mix, args.one_way_mix,
                               key, key_size, args.fanout);
        switch (err) {
        case CTX_ERR_UNKNOWN_MIX:
                errmsg("no mix primitive implementation found");
                err = ERR_UNKNOWN_MIX;
                goto cleanup;
        case CTX_ERR_MISSING_MIX:
                errmsg("cannot encrypt without a mix primitive");
                err = ERR_MISSING_MIX;
                goto cleanup;
        case CTX_ERR_UNKNOWN_ONE_WAY_MIX:
                errmsg("no one-way mix primitive implementation found");
                err = ERR_UNKNOWN_ONE_WAY_MIX;
                goto cleanup;
        case CTX_ERR_MISSING_ONE_WAY_MIX:
                errmsg("cannot use ofb encryption mode without a one-way primitive");
                err = ERR_MISSING_ONE_WAY_MIX;
                goto cleanup;
        case CTX_ERR_NOT_ONE_WAY:
                errmsg("expected a one-way primitive, but a symmetric mixing primitive was "
                       "provided");
                err = ERR_NOT_ONE_WAY;
                goto cleanup;
        case CTX_ERR_INCOMPATIBLE_PRIMITIVES:
                errmsg("the mix primitive and one-way primitive selected do not have a compatible "
                       "block size");
                err = ERR_INCOMPATIBLE_PRIMITIVES;
                goto cleanup;
        case CTX_ERR_EQUAL_PRIMITIVES:
                errmsg("cannot use ofb encryption mode with the same mix and one-way primitive");
                err = ERR_EQUAL_PRIMITIVES;
                goto cleanup;
        case CTX_ERR_KEYSIZE:
                mix_func_t mix_function;
                mix_func_t one_way_function;
                block_size_t block_size;
                block_size_t one_way_block_size;

                get_mix_func(args.mix, &mix_function, &block_size);
                switch (args.enc_mode) {
                case ENC_MODE_CTR:
                case ENC_MODE_CTR_OPT:
                        errmsg("size of the key must be: size = block_size * fanout^n, with "
                               "%s mixing primitive block_size = %d and fanout = %d",
                               get_mix_name(args.mix), block_size, args.fanout);
                        break;
                case ENC_MODE_OFB:
                        get_mix_func(args.one_way_mix, &one_way_function, &one_way_block_size);
                        errmsg("size of the key must be: size = block_size * fanout^n, with %s "
                               "mixing primitive block_size = %d and fanout = %d, but also "
                               "it must be a multiple of the one_way_block_size, with %s one-way "
                               "primitive one_way_block_size = %d", get_mix_name(args.mix),
                               block_size, get_mix_name(args.one_way_mix), one_way_block_size,
                               args.fanout);
                        break;
                }
                err = ERR_KEY_SIZE;
                goto cleanup;
        }

        if (stream_encrypt(&ctx, fin, fout, args.iv, args.threads))
                err = ERR_ENC;

        // ctx_keymix_init(&ctx, args.mixfunc, key, key_size, args.fanout);
        // err = stream_encrypt2(&ctx, fin, fout, args.iv, args.threads);

cleanup:
        safe_explicit_bzero(key, key_size);
        free(key);
        if (fkey != NULL)
                fclose(fkey);
        // Do NOT close stdin or stdout
        if (args.input != NULL && fin != NULL)
                fclose(fin);
        if (args.output != NULL && fout != NULL)
                fclose(fout);
        return err;
}
