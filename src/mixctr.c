#include "mixctr.h"

#include "aesni.h"
#include "openssl.h"
#include "types.h"
#include "wolfssl.h"
#include <string.h>

inline mixctrpass_impl_t get_mixctr_impl(mixctrpass_t name) {
        switch (name) {
        case MIXCTRPASS_WOLFSSL:
                return &wolfssl;
        case MIXCTRPASS_OPENSSL:
                return &openssl;
        case MIXCTRPASS_AESNI:
                return &aesni;
        default:
                return NULL;
        }
}

mixctrpass_t mixctr_from_str(char *name) {
        if (strcmp("wolfssl", name) == 0)
                return MIXCTRPASS_WOLFSSL;

        if (strcmp("openssl", name) == 0)
                return MIXCTRPASS_OPENSSL;

        if (strcmp("aesni", name) == 0)
                return MIXCTRPASS_AESNI;

        return -1;
}
