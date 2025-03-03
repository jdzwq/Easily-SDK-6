﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdk share document

	@module	impshare.h | interface file

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

#ifndef _IMPSHARE_H
#define _IMPSHARE_H

#include "../xdkdef.h"

#ifdef XDK_SUPPORT_SHARE

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION xshare_srv: create a share memory file server, and read local file data as it content.
@INPUT const tchar_t* pname: share memory file server name.
@INPUT const tchar_t* fpath: the file path name.
@INPUT dword_t hoff: the high word of file start position.
@INPUT dword_t hoff: the lower word of file start position.
@INPUT dword_t size: the share memory size.
@RETURN xhand_t: if succeeds return share memory handle, fails return NULL.
*/
EXP_API xhand_t xshare_srv(const tchar_t* pname, const tchar_t* fpath, dword_t hoff, dword_t loff, dword_t size);

/*
@FUNCTION xshare_cli: create a share memory client, and connect to named pipe server.
@INPUT const tchar_t* bname: share memory server name to connect.
@INPUT dword_t size: the share memory size, to open exist name object, then size can be zero, otherwise to create new name object, the size must not be zero.
@INPUT dword_t fmode: the file open mode, can be FILE_OPEN_READ, FILE_OPEN_WRITE, FILE_OPEN_APPEND or combined.
@RETURN xhand_t: if succeeds return pipe handle, fails return NULL.
*/
EXP_API xhand_t xshare_cli(const tchar_t* bname, dword_t size, dword_t fmode);

/*
@FUNCTION xshare_close: free share memory server or client handle.
@INPUT xhand_t sh: share memory handle.
@RETURN void: none.
*/
EXP_API void xshare_close(xhand_t sh);

/*
@FUNCTION xshare_handle: get system resource handle attached.
@INPUT xhand_t sh: share memory handle.
@RETURN res_file_t: system resource handle if exists, else return NULL.
*/
EXP_API res_file_t xshare_handle(xhand_t sh);

/*
@FUNCTION xshare_write: write data to pipe.
@INPUT xhand_t sh: share memory handle.
@INPUT const byte_t* buf: data buffer pointer.
@INOUTPUT dword_t* pb: integer variable indicate total bytes to write, and return actually bytes writed.
@RETURN bool_t: if succeeds return nonezero, fails return zero.
*/
EXP_API bool_t xshare_write(xhand_t sh, const byte_t* data, dword_t* pb);

/*
@FUNCTION xshare_read: read data from pipe.
@INPUT xhand_t sh: share memory handle.
@OUTPUT byte_t* buf: data buffer pointer.
@INOUTPUT dword_t* pb: integer variable indicate total bytes to read, and return actually bytes readed.
@RETURN bool_t: if succeeds return nonezero, fails return zero.
*/
EXP_API bool_t xshare_read(xhand_t sh, byte_t* buf, dword_t* pb);

/*
@FUNCTION xshare_lock: lock share memory inner buffer pointer from the position.
@INPUT xhand_t sh: share memory handle.
@INPUT dword_t offset: the start position.
@INPUT dword_t size: the locked buffer size.
@RETURN void*: if succeeds return buffer pointer, fails return NULL.
*/
EXP_API void* xshare_lock(xhand_t sh, dword_t offset, dword_t size);

/*
@FUNCTION xshare_unlock: unlock share memory inner buffer pointer from the position.
@INPUT xhand_t sh: share memory handle.
@INPUT dword_t offset: the start position.
@INPUT dword_t size: the already locked buffer size.
@INPUT void* p: the original returned buffer pointer.
@RETURN void*: if succeeds return buffer pointer, fails return NULL.
*/
EXP_API void xshare_unlock(xhand_t sh, dword_t offset, dword_t size, void* p);

#ifdef	__cplusplus
}
#endif

#endif /*XDK_SUPPORT_SHARE*/

#endif /*_IMPSHARE_H*/
