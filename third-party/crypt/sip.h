/**
* \file aes.h
*/
#ifndef SIP_H
#define SIP_H

#include <stddef.h>
#include <stdint.h>

#include "../tp_def.h"

uint64_t siphash(const unsigned char *in, uint32_t inlen, const unsigned char *k);

uint64_t siphash_nocase(const unsigned char *in, uint32_t inlen, const unsigned char *k);

#ifdef __cplusplus
extern "C" {
#endif

	OEM_EXP_API void siphash64(const unsigned char *in, uint32_t inlen, unsigned char out[8]);

#ifdef __cplusplus
}
#endif

#endif /* oemsip.h */

