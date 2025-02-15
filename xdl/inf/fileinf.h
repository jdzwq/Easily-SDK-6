/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdl file document

	@module	file.h | interface file

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

#ifndef _FILEINF_H
#define _FILEINF_H

typedef xhand_t(*PF_FIO_OPEN)(const secu_desc_t*, const tchar_t*, dword_t);
typedef bool_t(*PF_FIO_READ)(xhand_t, byte_t*, dword_t*);
typedef bool_t(*PF_FIO_WRITE)(xhand_t, const byte_t*, dword_t*);
typedef bool_t(*PF_FIO_READ_RANGE)(xhand_t, dword_t, dword_t, byte_t*, dword_t);
typedef bool_t(*PF_FIO_WRITE_RANGE)(xhand_t, dword_t, dword_t, const byte_t*, dword_t);
typedef bool_t(*PF_FIO_FLUSH)(xhand_t);
typedef void(*PF_FIO_CLOSE)(xhand_t);
typedef bool_t(*PF_FIO_SETOPT)(xhand_t, int, void*, int);
typedef bool_t(*PF_FIO_GETOPT)(xhand_t, int, void*, int);

typedef struct _file_interface{
	xhand_t		fd;

	PF_FIO_WRITE		pf_write;
	PF_FIO_FLUSH		pf_flush;
	PF_FIO_READ			pf_read;
	PF_FIO_READ_RANGE	pf_read_range;
	PF_FIO_WRITE_RANGE	pf_write_range;
	PF_FIO_CLOSE		pf_close;
	PF_FIO_SETOPT		pf_setopt;
	PF_FIO_GETOPT		pf_getopt;
}file_interface, *file_t;

#endif /*FILE_H*/
