/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc uio interface document

	@module	uioinf.h | interface file

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

#ifndef _UIOINF_H
#define _UIOINF_H


typedef bool_t(*PF_UIO_PUSH)(xhand_t, const byte_t*, dword_t*);
typedef bool_t(*PF_UIO_POP)(xhand_t, byte_t*, dword_t*);
typedef bool_t(*PF_UIO_PEEK)(xhand_t,byte_t*, dword_t*);
typedef void(*PF_UIO_CLOSE)(xhand_t);

typedef struct _uio_interface{
	xhand_t		fd;

	PF_UIO_PUSH		pf_push;
	PF_UIO_POP		pf_pop;
	PF_UIO_PEEK		pf_peek;
	PF_UIO_CLOSE	pf_close;
}uio_interface;



#endif /*_UIOINF_H*/