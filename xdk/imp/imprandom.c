/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc random document

	@module	imprandom.c | implement file

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

#include "imprandom.h"

#include "../xdkstd.h"
#include "../xdkimp.h"

#ifdef XDK_SUPPORT_RANDOM

void system_srand()
{
	if_random_t* pif;

	pif = PROCESS_RANDOM_INTERFACE;

	XDK_ASSERT(pif != NULL);

	(*pif->pf_system_srand)();
}

dword_t system_rand32()
{
	if_random_t* pif;

	pif = PROCESS_RANDOM_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_system_rand32)();
}

lword_t system_rand64()
{
	if_random_t* pif;

	pif = PROCESS_RANDOM_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_system_rand64)();
}

#endif /*XDK_SUPPORT_RANDOM*/
