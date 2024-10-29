#include "kravette-wbc.h"

#include <stdlib.h>
#include <string.h>

#include <xkcp/Kravatte.h>
#include <xkcp/KravatteModes.h>

#include "log.h"
#include "mix.h"
#include "types.h"

// --- XKCP Kravatte-WBC in ECB mode ---
int xkcp_kravette_wbc_ecb(byte *in, byte *out, size_t size, byte *iv) {
        Kravatte_Instance kwiEnc;

        int result = Kravatte_WBC_Initialize(&kwiEnc, iv, 8 * strlen(iv)); // max 1600 bit key
        if (result) {
                _log(LOG_ERROR, "Kravatte_WBC_Initialize error %d\n", result);
        }

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_KRAVETTE_WBC, out += BLOCK_SIZE_KRAVETTE_WBC) {
                result = Kravatte_WBC_Encipher(&kwiEnc, in, out, 8 * BLOCK_SIZE_KRAVETTE_WBC, NULL, 0); // ignore tweakable part
                if (result) {
                        _log(LOG_ERROR, "Kravatte_WBC_Encipher error %d\n", result);
                }
        }
        return 0;
}
