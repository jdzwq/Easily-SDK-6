/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc ssl premaster document

	@module	sslprf.h | interface file

	@devnote 张文权 2021.01 - 2021.12	v6.0
***********************************************************************/

/**********************************************************************
This program is free software : you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
LICENSE.GPL3 for more details.
***********************************************************************/

#ifndef _SSLPRF_H
#define _SSLPRF_H

#include <stddef.h>
#include <stdint.h>

#include "../tp_def.h"

#ifdef	__cplusplus
extern "C" {
#endif

	/*for SSL3.0*/
	OEM_EXP_API void ssl_prf0(unsigned char *secret, int slen, unsigned char *random, int rlen, unsigned char *dstbuf, int dlen);

	/*for TLS1.0 TLS1.1*/
	OEM_EXP_API void ssl_prf1(unsigned char *secret, int slen, char *label, unsigned char *random, int rlen, unsigned char *dstbuf, int dlen);

	/*for TLS1.2*/
	OEM_EXP_API void ssl_prf2(unsigned char *secret, int slen, char *label, unsigned char *random, int rlen, unsigned char *dstbuf, int dlen);

	/*for TLS1.3*/
	OEM_EXP_API void ssl_extract(int md_alg, const unsigned char *ikm, int ilen, const unsigned char *salt, int slen, unsigned char *prk, int* plen);
	OEM_EXP_API void ssl_expand(int md_alg, const unsigned char* prk, int klen, const char* label, const unsigned char* hash, int hlen, unsigned char* okm, int olen);

#ifdef	__cplusplus
}
#endif

#endif /*XDNINET_H*/