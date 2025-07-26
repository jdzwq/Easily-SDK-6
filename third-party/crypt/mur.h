/**
* \file aes.h
*/
#ifndef MUR_H
#define MUR_H

#include <stddef.h>
#include <stdint.h>

#include "../tp_def.h"

uint32_t MurmurHash3_x86_32(const void * key, int len, uint32_t seed);
void MurmurHash3_x86_128(const void * key, int len, uint32_t seed, void * out);
void MurmurHash3_x64_128(const void * key, int len, uint32_t seed, void * out);

#ifdef __cplusplus
extern "C" {
#endif

	OEM_EXP_API void murhash32(const unsigned char *in, uint32_t inlen, unsigned char out[4]);

	OEM_EXP_API void murhash128(const unsigned char *in, uint32_t inlen, unsigned char out[16]);

#ifdef __cplusplus
}
#endif

#endif /* oemmur.h */

