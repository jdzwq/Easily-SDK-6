/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdk utility document

	@module	points.h | interface file

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

#ifndef _POINTS_H
#define _POINTS_H

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

EXP_API int ft_parse_points_from_token(xpoint_t* ppt, int max, const tchar_t* token, int len);

EXP_API int ft_format_points_to_token(const xpoint_t* ppt, int n, tchar_t* buf, int max);

EXP_API int pt_parse_points_from_token(xpoint_t* ppt, int max, const tchar_t* token, int len);

EXP_API int pt_format_points_to_token(const xpoint_t* ppt, int n, tchar_t* buf, int max);

EXP_API int parse_dicm_point(const tchar_t* token, int len, xpoint_t* ppt, int max);

EXP_API int format_dicm_point(const xpoint_t* ppt, int count, tchar_t* buf, int max);

EXP_API bool_t inside_rowcol(int row, int col, int from_row, int from_col, int to_row, int to_col);

EXP_API int compare_rowcol(int from_row, int from_col, int to_row, int to_col);


#ifdef	__cplusplus
}
#endif

#endif