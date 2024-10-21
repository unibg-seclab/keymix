#include "xoofff-wbc.h"

#include <stdlib.h>
#include <string.h>

#include <xkcp/Xoofff.h>
#include <xkcp/XoofffModes.h>

#include "log.h"
#include "mix.h"
#include "types.h"

// --- XKCP Xoofff-WBC in ECB mode ---
int xkcp_xoofff_wbc_ecb(byte *in, byte *out, size_t size) {
        Xoofff_Instance xpiEnc;
        BitSequence key[] = "4mGOOW8zXC7W79tL3vCVq15AEr7wNkb9"; // 256 bit key (max 384 bit)

        int result = XoofffWBC_Initialize(&xpiEnc, key, 8 * strlen(key));
        if (result) {
                _log(LOG_ERROR, "XoofffWBC_Initialize error %d\n", result);
        }

        byte *last = in + size;
        for (; in < last; in += XOOFFF_WBC_BLOCK_SIZE, out += XOOFFF_WBC_BLOCK_SIZE) {
                result = XoofffWBC_Encipher(&xpiEnc, in, out, 8 * XOOFFF_WBC_BLOCK_SIZE, NULL, 0); // ignore tweakable part
                if (result) {
                        _log(LOG_ERROR, "XoofffWBC_Encipher error %d\n", result);
                }
        }
        return 0;
}
