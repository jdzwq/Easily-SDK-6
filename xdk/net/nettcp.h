﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc tcp document

	@module	nettcp.h | interface file

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

#ifndef _NETTCP_H
#define _NETTCP_H

#include "../xdkdef.h"
#include "netdef.h"

#ifdef XDK_SUPPORT_SOCK

#define TCP_BASE_TIMO		(5000) //milloinsecond
#define TCP_MIN_SNDBUFF		(4096)
#define TCP_MIN_RCVBUFF		(4096)
#define TCP_MAX_SNDBUFF		(16 * 1024 * 1024)
#define TCP_MAX_RCVBUFF		(8 * 1024 * 1024)

typedef enum{
	_XTCP_TYPE_LIS = 0,
	_XTCP_TYPE_CLI = 1,
	_XTCP_TYPE_SRV = 2
}XTCP_TYPE;


#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION xtcp_cli: create a TCP client.
@INPUT unsigned short port: the network port to connect.
@INPUT const tchar_t* addr: the network address to connect.
@RETURN xhand_t: if succeeds return TCP client handle, fails return NULL.
*/
EXP_API xhand_t xtcp_cli(unsigned short port, const tchar_t* addr);

/*
@FUNCTION xtcp_srv: create a TCP server.
@INPUT res_file_t so: the network io resource handle, it must be a socket resource handle.
@RETURN xhand_t: if succeeds return TCP server handle, fails return NULL.
*/
EXP_API xhand_t xtcp_srv(res_file_t so);

/*
@FUNCTION xtcp_socket: get socket resource handle.
@INPUT xhand_t tcp: the TCP handle.
@RETURN res_file_t: return the socket resource handle.
*/
EXP_API res_file_t xtcp_socket(xhand_t tcp);

/*
@FUNCTION xtcp_type: get socket type, it can be _XTCP_TYPE_CLI, _XTCP_TYPE_SRV.
@INPUT xhand_t tcp: the TCP handle.
@RETURN int: return the socket type.
*/
EXP_API int  xtcp_type(xhand_t tcp);

/*
@FUNCTION xtcp_close: close TCP handle.
@INPUT xhand_t tcp: the TCP handle.
@RETURN void: none.
*/
EXP_API void  xtcp_close(xhand_t tcp);

/*
@FUNCTION xtcp_write: write TCP data.
@INPUT xhand_t tcp: the TCP handle.
@INPUT const byte_t* data: the data buffer.
@INOUTPUT dword_t* pb: indicate the bytes to write and return the bytes writed.
@RETURN bool_t: if succeeds return nonzero, failed return zero.
*/
EXP_API bool_t  xtcp_write(xhand_t tcp, const byte_t* data, dword_t* pb);

/*
@FUNCTION xtcp_read: read TCP data.
@INPUT xhand_t tcp: the TCP handle.
@OUTPUT byte_t* data: the data buffer.
@INOUTPUT dword_t* pb: indicate the bytes to read and return the bytes readed.
@RETURN bool_t: if succeeds return nonzero, failed return zero.
*/
EXP_API bool_t  xtcp_read(xhand_t tcp, byte_t* data, dword_t* pb);

/*
@FUNCTION xtcp_setopt: set the socket options.
@INPUT xhand_t tcp: the tcp handle.
@INPUT int oid: the option id, eg: SOCK_OPTION_SNDBUF, SOCK_OPTION_RCVBUF, SOCK_OPTION_NONBLK.
@INPUT void* opt: the option value pointer
@INPUT int len: the value length in bytes, string value must be a zero terminated token and set len to zero.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t xtcp_setopt(xhand_t tcp, int oid, void* opt, int len);

/*
@FUNCTION xtcp_settmo: set the socket timeout.
@INPUT xhand_t tcp: the tcp handle.
@INPUT dword_t tmo: the tmieout in millsecoend.
@RETURN void: none
*/
EXP_API void xtcp_settmo(xhand_t tcp, dword_t tmo);

/*
@FUNCTION xtcp_addr_port: get TCP local address and port.
@INPUT xhand_t tcp: the TCP handle.
@OUTPUT tchar_t* addr: the string buffer.
@RETURN unsigned short: return the local port.
*/
EXP_API unsigned short xtcp_addr_port(xhand_t tcp, tchar_t* addr);

/*
@FUNCTION xtcp_peer_port: get TCP remote address and port.
@INPUT xhand_t tcp: the TCP handle.
@OUTPUT tchar_t* addr: the string buffer.
@RETURN unsigned short: return the remote port.
*/
EXP_API unsigned short xtcp_peer_port(xhand_t tcp, tchar_t* addr);

#ifdef	__cplusplus
}
#endif

#endif /*XDK_SUPPORT_SOCK*/

#endif /*IMPSOCK_H*/