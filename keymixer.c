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
        uint128_t iv;
        unsigned int fanout;
        mixctr_t mixfunc;
        unsigned int threads;
        unsigned short verbose;
} cli_args_t;

enum args_key {
        ARG_KEY_INPUT   = 'i',
        ARG_KEY_OUTPUT  = 'o',
        ARG_KEY_SECRET  = 's',
        ARG_KEY_FANOUT  = 'f',
        ARG_KEY_LIBRARY = 'l',
        ARG_KEY_THREADS = 't',
        ARG_KEY_VERBOSE = 'v',
        ARG_KEY_IV      = 1, // Not a printable char = no short option
};

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
    {"input", ARG_KEY_INPUT, "PATH", 0, "Path of the resource to protect"},
    {"output", ARG_KEY_OUTPUT, "PATH", 0, "Path of the output result (default is [input].enc)"},
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

static struct argp argp = {options, parse_opt, "",
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
                arguments->iv          = 0;
                arguments->fanout      = 3;
                arguments->mixfunc     = MIXCTR_WOLFSSL;
                arguments->threads     = 1;
                arguments->verbose     = false;
                break;
        case ARG_KEY_INPUT:
                arguments->input = arg;
                break;
        case ARG_KEY_OUTPUT:
                arguments->output = arg;
                break;
        case ARG_KEY_SECRET:
                arguments->secret_path = arg;
                break;
        case ARG_KEY_IV:
                if (strlen(arg) != 16) {
                        ERROR_MSG("Invalid IV: must be 16 Bytes\n");
                        goto arg_error;
                }

                if (hex2int(&(arguments->iv), arg)) {
                        ERROR_MSG("Invalid IV: must consist of valid hex characters\n");
                        goto arg_error;
                }
                break;
        case ARG_KEY_FANOUT:
                arguments->fanout = atoi(arg);
                if (!is_valid_fanout(arguments->fanout)) {
                        ERROR_MSG("Invalid fanout, valid values are 2, 3, or 4\n");
                        goto arg_error;
                }
                break;
        case ARG_KEY_LIBRARY:
                arguments->mixfunc = mixctr_from_str(arg);
                if (arguments->mixfunc == -1) {
                        ERROR_MSG("Invalid LIBRARY -- choose among wolfssl, openssl, aesni\n");
                        goto arg_error;
                }
                break;
        case ARG_KEY_THREADS:
                arguments->threads = atoi(arg);
                if (arguments->threads < 1 || arguments->threads > 128) {
                        ERROR_MSG("Unsupported number of threads, at least 1 and at most 128\n");
                        goto arg_error;
                }
                break;
        case ARG_KEY_VERBOSE:
                arguments->verbose = true;
                break;
        case ARGP_KEY_END:
                missing = 0;
                missing += check_missing(arguments->input, "input file");
                missing += check_missing(arguments->secret_path, "secret file");
                if (missing > 0)
                        goto arg_error;

                if (arguments->output == NULL) {
                        size_t in_len = strlen(arguments->input);

                        // Allocate with space for ".enc" (4) and '\n' (1)
                        arguments->output = malloc(in_len + 4 + 1);
                        strcpy(arguments->output, arguments->input);
                        strcpy(arguments->output + in_len, ".enc");
                }
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
                return 0;
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
        ctx_encrypt_init(&ctx, args.mixfunc, key, key_size, args.iv, args.fanout);

        // Do the encryption
        int err = file_encrypt(fout, fin, &ctx, args.threads);

cleanup:
        safe_explicit_bzero(key, key_size);
        free(key);
        safe_fclose(fkey);
        safe_fclose(fout);
        safe_fclose(fin);
        return errno || err;
}
