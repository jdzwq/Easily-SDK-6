/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdl file document

	@module	fileiml.h | interface file

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

#ifndef _FILESBIO_H
#define _FILESBIO_H

#include "../xdldef.h"

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION xfile_list: list a directory child items.
@INPUT const secu_desc_t* psd: the security struct for writing destination file.
@INPUT const tchar_t* path: the path name.
@INPUT link_t_ptr ptr: the list document link component.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t		xfile_list(const secu_desc_t* psd, const tchar_t* path, link_t_ptr ptr);

/*
@FUNCTION xfile_tree: list a directory child and all sub child items.
@INPUT const secu_desc_t* psd: the security struct for writing destination file.
@INPUT const tchar_t* path: the path name.
@INPUT link_t_ptr ptr: the list document link component.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API void		xfile_tree(const secu_desc_t* psd, const tchar_t* path, link_t_ptr ptr);

/*
@FUNCTION xfile_dump: dump a directory child items.
@INPUT const secu_desc_t* psd: the security struct for writing destination file.
@INPUT const tchar_t* path: the path name.
@INPUT stream_t stm: the stream object.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t		xfile_dump(const secu_desc_t* psd, const tchar_t* path, stream_t stm);

#ifdef	__cplusplus
}
#endif


#endif /*FILE_H*/
