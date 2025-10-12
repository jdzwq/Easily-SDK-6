/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc defination document

	@module	xdfdef.h | interface file

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


#ifndef _XDFDEF_H
#define	_XDFDEF_H

#include <xdk.h>

#if defined(_OS_WINDOWS)
#include "windows/_xdf_windows.h"
#elif defined(_OS_MACOS)
#include "macos/_xdf_macos.h"
#elif defined(_OS_LINUX)
#include "linux/_xdf_linux.h"
#endif


//bluetooth device
typedef struct _dev_blt_t{
	tchar_t major_class[RES_LEN + 1];
	tchar_t minor_class[RES_LEN + 1];
	tchar_t name[META_LEN + 1];
	tchar_t uuid[UUID_LEN + 1];
	tchar_t addr[ADDR_LEN + 1];
}dev_blt_t;


#endif	/* _XDFDEF_H */

