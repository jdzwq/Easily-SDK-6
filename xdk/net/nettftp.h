﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdn tftp document

	@module	nettftp.h | interface file

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

#ifndef _NETTFTP_H
#define _NETTFTP_H

#include "../xdkdef.h"
#include "netdef.h"
#include "httpattr.h"

#if defined(XDK_SUPPORT_SOCK)

typedef enum{
	_XTFTP_TYPE_LIS = 0,
	_XTFTP_TYPE_CLI = 1,
	_XTFTP_TYPE_SRV = 2
}XTFTP_TYPE;

#define DEF_TFTP_PORT		69

#define TFTP_PKG_SIZE      516
#define TFTP_HDR_SIZE		2
#define TFTP_PDU_SIZE      514
#define TFTP_PDV_SIZE      (TFTP_PDU_SIZE - TFTP_HDR_SIZE)

#define TFTP_PDU_HEAD		0
#define TFTP_PDU_RRQ		1
#define TFTP_PDU_WRQ		2
#define TFTP_PDU_DATA		3
#define TFTP_PDU_ACK		4
#define TFTP_PDU_ERR		5
#define TFTP_PDU_DEL		6

#define TFTP_METHOD_GET		_T("GET")
#define TFTP_METHOD_PUT		_T("PUT")
#define TFTP_METHOD_HEAD	_T("HEAD")
#define TFTP_METHOD_DELETE	_T("DELETE")

#define TFTP_CODE_NOTDEF		0
#define TFTP_CODE_NOTDEF_TEXT	_T("Not defined")

#define TFTP_CODE_NOTFIND		1
#define TFTP_CODE_NOTFIND_TEXT	_T("File not found")

#define TFTP_CODE_REJECT		2
#define TFTP_CODE_REJECT_TEXT	_T("Access violation")

#define TFTP_CODE_DSKFULL		3
#define TFTP_CODE_DSKFULL_TEXT	_T("Disk full or allocation exceeded")

#define TFTP_CODE_ILLEGAL	4
#define TFTP_CODE_ILLEGAL_TEXT	_T("Illegal TFTP operation")

#define TFTP_CODE_UNTID		5
#define TFTP_CODE_UNTID_TEXT	_T("Unknown transfer ID")

#define TFTP_CODE_EXISTS		6
#define TFTP_CODE_EXISTS_TEXT	_T("File already exists")

#define TFTP_CODE_NOUSER		7
#define TFTP_CODE_NOUSER_TEXT	_T("No such user")

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION xtftp_client: create a TFTP client.
@INPUT const tchar_t* method: the TFTP method, it can be "GET", "PUT", "HEAD", "DELETE".
@INPUT const tchar_t* url: the TFTP service url.
@RETURN xhand_t: if succeeds return TFTP client handle, fails return NULL.
*/
EXP_API xhand_t		xtftp_client(const tchar_t* method, const tchar_t* url);

/*
@FUNCTION xtftp_server: create a TFTP server.
@INPUT xhand_t bio: the net io handle, it may be udp or dtls handle.
@RETURN xhand_t: if succeeds return TFTP server handle, fails return NULL.
*/
EXP_API xhand_t		xtftp_server(xhand_t bio);

/*
@FUNCTION xtftp_bio: get the TFTP udp bio handle.
@INPUT xhand_t tftp: the tftp handle.
@RETURN xhand_t: return the udp handle.
*/
EXP_API xhand_t		xtftp_bio(xhand_t tftp);

/*
@FUNCTION xtftp_method: get a TFTP method.
@INPUT xhand_t tftp: the TFPT handle.
@OUTPUT tchar_t* buf: the string buffer for returning method.
@INPUT int max: the buffer size in characters.
@RETURN int: return the method token length in characters.
*/
EXP_API int			xtftp_method(xhand_t tftp, tchar_t* buf, int max);

/*
@FUNCTION xtftp_close: close the TFPT handle.
@INPUT xhand_t tftp: the TFPT handle.
@RETURN void: none.
*/
EXP_API void		xtftp_close(xhand_t tftp);

/*
@FUNCTION xtftp_connect: client connect to server.
@INPUT xhand_t tftp: the TFPT handle.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t		xtftp_connect(xhand_t tftp);

/*
@FUNCTION xtftp_accept: server accept client request.
@INPUT xhand_t tftp: the TFPT handle.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t		xtftp_accept(xhand_t tftp);

/*
@FUNCTION xtftp_send: send TFPT data.
@INPUT xhand_t tftp: the TFPT handle.
@INPUT const byte_t* data: the data bytes buffer.
@INOUTPUT dword_t* pb: indicate the bytes to send and return the bytes sended.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t		xtftp_send(xhand_t tftp, const byte_t* data, dword_t *pb);

/*
@FUNCTION xtftp_flush: ensure TFPT data sending compeleted.
@INPUT xhand_t tftp: the TFPT handle.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t		xtftp_flush(xhand_t tftp);

/*
@FUNCTION xtftp_recv: recv TFPT data.
@INPUT xhand_t tftp: the TFPT handle.
@INPUT const byte_t* data: the bytes buffer for receiving.
@INOUTPUT dword_t* pb: indicate the bytes to read and return the bytes readed.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t		xtftp_recv(xhand_t tftp, byte_t* buf, dword_t *pb);

/*
@FUNCTION xtftp_abort: abort a TFPT operation, it must be called by TFTP server.
@INPUT xhand_t tftp: the TFPT handle.
@INPUT int errcode: the TFTP error code.
@RETURN void: none.
*/
EXP_API void		xtftp_abort(xhand_t tftp, int errcode);
	
/*
@FUNCTION xtftp_set_isdir: set TFPT current object is a directory.
@INPUT xhand_t tftp: the TFPT handle.
@INPUT bool_t dir: nonezero for directory object, zero for file object.
@RETURN void: none.
*/
EXP_API void		xtftp_set_isdir(xhand_t tftp, bool_t dir);

/*
@FUNCTION xtftp_get_isdir: get TFPT current object is a directory.
@INPUT xhand_t tftp: the TFPT handle.
@RETURN bool_t: return nonezero for directory object, zero for file object..
*/
EXP_API bool_t		xtftp_get_isdir(xhand_t tftp);

/*
@FUNCTION xtftp_set_filesize: set TFPT current object file size.
@INPUT xhand_t tftp: the TFPT handle.
@INPUT dword_t size: the file size in bytes.
@RETURN void: none.
*/
EXP_API void		xtftp_set_filesize(xhand_t tftp, dword_t size);

/*
@FUNCTION xtftp_get_filesize: get TFPT current object file size.
@INPUT xhand_t tftp: the TFPT handle.
@RETURN dword_t: return the file size in bytes.
*/
EXP_API dword_t		xtftp_get_filesize(xhand_t tftp);

/*
@FUNCTION xtftp_set_filetime: set TFPT current object file time.
@INPUT xhand_t tftp: the TFPT handle.
@INPUT const tchar_t* ftime: the file GMT time token.
@RETURN void: none.
*/
EXP_API void		xtftp_set_filetime(xhand_t tftp, const tchar_t* ftime);

/*
@FUNCTION xtftp_get_filetime: get TFPT current object file time.
@INPUT xhand_t tftp: the TFPT handle.
@OUTPUT tchar_t* ftime: the string buffer for returning file GMT time.
@RETURN void: none.
*/
EXP_API void		xtftp_get_filetime(xhand_t tftp, tchar_t* ftime);

/*
@FUNCTION xtftp_set_filename: set TFPT current object file name.
@INPUT xhand_t tftp: the TFPT handle.
@INPUT const tchar_t* fname: the file name token.
@RETURN void: none.
*/
EXP_API void		xtftp_set_filename(xhand_t tftp, const tchar_t* fname);

/*
@FUNCTION xtftp_get_filename: get TFPT current object file name.
@INPUT xhand_t tftp: the TFPT handle.
@OUTPUT tchar_t* ftime: the string buffer for returning file name.
@RETURN void: none.
*/
EXP_API void		xtftp_get_filename(xhand_t tftp, tchar_t* fname);

EXP_API bool_t		xtftp_head(xhand_t tftp);

EXP_API bool_t		xtftp_delete(xhand_t tftp);

EXP_API void		xtftp_settmo(xhand_t tftp, dword_t tmo);

#ifdef	__cplusplus
}
#endif

#endif /*XDK_SUPPORT_SOCK*/

#endif /*XDNINET_H*/