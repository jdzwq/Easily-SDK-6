/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc random system call document

	@module	_if_random.c | windows implement file

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

#include "../xdkloc.h"

#ifdef XDK_SUPPORT_RANDOM
void _system_srand()
{
	NOP;
}

dword_t _system_rand32()
{
	dword_t pn;

	HCRYPTPROV provider;
	BYTE buf[4];

	if (CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE)
	{
		return 0;
	}

	if (CryptGenRandom(provider, 4, buf) == FALSE)
	{
		CryptReleaseContext(provider, 0);
		return 0;
	}

	pn = GET_DWORD_LIT(buf, 0);

	CryptReleaseContext(provider, 0);

	return pn;
}

lword_t _system_rand64()
{
	lword_t pn;
	HCRYPTPROV provider;
	BYTE buf[8];

	if (CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE)
	{
		return 0;
	}

	if (CryptGenRandom(provider, 8, buf) == FALSE)
	{
		CryptReleaseContext(provider, 0);
		return 0;
	}

	pn = GET_LWORD_LIT(buf, 0);

	CryptReleaseContext(provider, 0);

	return pn;
}

#endif //XDK_SUPPORT_RANDOM