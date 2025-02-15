/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc graphic dotting document

	@module	dot.h | interface file

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

#ifndef _DOT_H
#define _DOT_H

#include "../xdkdef.h"

#define DOT_SOLID			0x00
#define DOT_DASH			0x55
#define DOT_DASHDASH		0x66
#define DOT_DASHDASHDASH	0x77

#define SLIC_TOP			0x01
#define SLIC_BOTTOM			0x02
#define SLIC_LEFT			0x04
#define SLIC_RIGHT			0x08


#ifdef	__cplusplus
extern "C" {
#endif

	EXP_API int dot_line(int dot_width, int dot_mode, int xoff, int yoff, xpoint_t* ppt_buffer, int size_buffer);

	EXP_API int dot_rect(int dot_width, int dot_mode, int width, int height, xpoint_t* ppt_buffer, int size_buffer);

	EXP_API int dot_ellipse(int dot_width, int dot_mode, int rx, int ry, xpoint_t* ppt_buffer, int size_buffer);

	EXP_API int dot_arc(int dot_width, int dot_mode, int rx, int ry, double angle_from, double angle_to, bool_t clockwise, xpoint_t* ppt_buffer, int size_buffer);

	EXP_API int dot_curve2(int dot_width, int dot_mode, const xpoint_t* ppt1, const xpoint_t* ppt2, xpoint_t* ppt_buffer, int size_buffer);

	EXP_API int dot_curve3(int dot_width, int dot_mode, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt4, xpoint_t* ppt_buffer, int size_buffer);


#ifdef	__cplusplus
}
#endif

#endif /*_DOT_H*/
