/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdf interface document

	@module	xdfinf.h | interface file

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

#ifndef _XDFINF_H
#define	_XDFINF_H

#include "xdfdef.h"

#ifdef XDF_SUPPORT_BLUT
typedef int(*PF_ENUM_BLUT)(dev_blt_t*, int);
typedef res_file_t(*PF_BLUT_OPEN)(const tchar_t*, int, dword_t);
typedef void(*PF_BLUT_CLOSE)(res_file_t);
typedef dword_t(*PF_BLUT_LISTEN)(res_file_t, async_t*);
typedef bool_t(*PF_BLUT_READ)(res_file_t, void*, dword_t, async_t*);
typedef bool_t(*PF_BLUT_WRITE)(res_file_t, void*, dword_t, async_t*);
typedef bool_t(*PF_BLUT_FLUSH)(res_file_t);

typedef struct _if_blut_t{
	PF_ENUM_BLUT	pf_enum_blut;
	PF_BLUT_LISTEN		pf_blut_listen;
	PF_BLUT_OPEN		pf_blut_open;
	PF_BLUT_CLOSE		pf_blut_close;
	PF_BLUT_READ		pf_blut_read;
	PF_BLUT_WRITE		pf_blut_write;
	PF_BLUT_FLUSH		pf_blut_flush;
}if_blut_t;
#endif


#ifdef	__cplusplus
extern "C" {
#endif

#ifdef XDF_SUPPORT_BLUT
	EXP_API void xdf_impl_blut(if_blut_t* pif);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _XDFINF_H */

