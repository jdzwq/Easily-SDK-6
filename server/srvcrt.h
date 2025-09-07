/***********************************************************************
	Easily Port Service

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, China ZheJiang HangZhou JianDe, Mail: powersuite@hotmaol.com

	@doc service defination document

	@module	srvcert.h | service definition interface file

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


#ifndef _SRVCRT_H
#define _SRVCRT_H

#include "srvdef.h"

bool_t get_ssl_crt(const tchar_t* path, const tchar_t* name, byte_t* buf, dword_t* pb);

bool_t get_ssl_key(const tchar_t* path, const tchar_t* name, byte_t* buf, dword_t* pb);

bool_t get_ssh_key(const tchar_t* path, const tchar_t* name, byte_t* buf, dword_t* pb);


#endif //_SRVCERT_H