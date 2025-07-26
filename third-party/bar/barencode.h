

#ifndef __BARENCODDE_H__
#define __BARENCODDE_H__

#include <stddef.h>
#include <stdint.h>

#include "../tp_def.h"

#define PDF417_USE_ASPECT_RATIO     0
#define PDF417_FIXED_RECTANGLE      1
#define PDF417_FIXED_COLUMNS        2
#define PDF417_FIXED_ROWS           4
#define PDF417_AUTO_ERROR_LEVEL     0
#define PDF417_USE_ERROR_LEVEL      16
#define PDF417_USE_RAW_CODEWORDS    64
#define PDF417_INVERT_BITMAP        128

#define PDF417_ERROR_SUCCESS        0
#define PDF417_ERROR_TEXT_TOO_BIG   1
#define PDF417_ERROR_INVALID_PARAMS 2

typedef struct _pdf417param {
	char *outBits;
	int lenBits;
	int bitColumns;
	int codeRows;
	int codeColumns;
	int codewords[928];
	int lenCodewords;
	int errorLevel;
	char *text;
	int lenText;
	int options;
	float aspectRatio;
	float yHeight;
	int error;
} pdf417param, *pPdf417param;

typedef struct _code128param {
	char *inText;
	int lenText;
	char *outBytes;
	int lenBytes;
	int codeColumns;
	int error;
} code128param;

#ifdef __cplusplus
extern "C" {
#endif

OEM_EXP_API void pdf417init(pPdf417param param);
OEM_EXP_API void paintCode(pPdf417param p) ;
OEM_EXP_API void pdf417free(pPdf417param param) ;

OEM_EXP_API void code128init(code128param* p);
OEM_EXP_API void code128free(code128param* p);
OEM_EXP_API void code128exec(code128param* p);

#ifdef __cplusplus
}
#endif

#endif /* __BARENCODDE_H__ */
