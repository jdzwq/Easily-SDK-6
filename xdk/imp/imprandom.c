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

void system_random32(dword_t* pn)
{
	if_random_t* pif;

	pif = PROCESS_RANDOM_INTERFACE;

	XDK_ASSERT(pif != NULL);

	(*pif->pf_system_random32)(pn);
}

void system_random64(lword_t* pn)
{
	if_random_t* pif;

	pif = PROCESS_RANDOM_INTERFACE;

	XDK_ASSERT(pif != NULL);

	(*pif->pf_system_random64)(pn);
}

#endif /*XDK_SUPPORT_RANDOM*/
