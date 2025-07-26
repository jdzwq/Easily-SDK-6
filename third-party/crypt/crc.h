#ifndef CRC_H
#define CRC_H

#include <stddef.h>
#include <stdint.h>

#include "../tp_def.h"

#ifdef __cplusplus
extern "C" {
#endif

	OEM_EXP_API uint16_t crc16(const unsigned char *s, uint16_t l);

	OEM_EXP_API uint32_t crc32(uint32_t crc, const unsigned char *s, uint32_t l);

	OEM_EXP_API uint64_t crc64(uint64_t crc, const unsigned char *s, uint64_t l);

#ifdef __cplusplus
}
#endif


#endif

