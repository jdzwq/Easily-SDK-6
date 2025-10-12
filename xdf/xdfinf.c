/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdf document

	@module	xdfinf.c | implement file

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

#include "xdfinf.h"
#include "xdfloc.h"

#ifdef XDF_SUPPORT_BLUT
void xdf_impl_blut(if_blut_t* pif)
{
	pif->pf_enum_blut = _enum_blut_device;
	pif->pf_blut_listen = _blut_listen;
	pif->pf_blut_open = _blut_open;
	pif->pf_blut_close = _blut_close;
	pif->pf_blut_read = _blut_read;
	pif->pf_blut_write = _blut_write;
	pif->pf_blut_flush = _blut_flush;
}
#endif
