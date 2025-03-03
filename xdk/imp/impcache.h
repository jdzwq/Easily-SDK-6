﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc memory cache document

	@module	impcache.h | interface file

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

#ifndef _IMPCACHE_H
#define	_IMPCACHE_H

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif


#ifdef XDK_SUPPORT_MEMO_CACHE
/*
@FUNCTION xcache_open: open a memory cache.
@RETURN xhand_t: if succeeds return cache handle, fails return NULL.
*/
EXP_API xhand_t xcache_open(void);

/*
@FUNCTION xcache_close: close a memory cache.
@INPUT xhand_t cache: the cache handle.
@RETURN void: none.
*/
EXP_API void xcache_close(xhand_t vmem);

/*
@FUNCTION xcache_handle: get a cache handle, the handle is buffer pointer.
@INPUT xhand_t vmem: the cache handle.
@RETURN void*: if succeeds return buffer pointer, fails return NULL.
*/
EXP_API void* xcache_handle(xhand_t vmem);

/*
@FUNCTION xcache_write: write data into cache.
@INPUT xhand_t vmem: the cache handle.
@INPUT const byte_t* data: the data buffer pointer.
@INOUTPUT dword_t* pb: the integer buffer pointer holding byte count for writing, and return the actually byte count writed.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t xcache_write(xhand_t vmem, const byte_t* data, dword_t* pb);

/*
@FUNCTION xcache_read: read data from cache.
@INPUT xhand_t vmem: the cache handle.
@INPUT byte_t* data: the data buffer pointer.
@INOUTPUT dword_t* pb: the integer buffer pointer for holding byte count for reading, and return the actually byte count readed.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t xcache_read(xhand_t vmem, byte_t* buf, dword_t* pb);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/*IMPCACHE_H */

