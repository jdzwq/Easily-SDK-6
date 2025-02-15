/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc device independent bitmap document

	@module	dib.h | interface file

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
#ifndef _DIB_H
#define _DIB_H

#include "../xdkdef.h"
#include "../img/bmp.h"

#ifdef	__cplusplus
extern "C" {
#endif

	EXP_API dword_t fill_color_dibbits(const xcolor_t* pxc, const bitmap_info_head_t* pbi, const bitmap_quad_t* pbq, byte_t* bits, dword_t max);

	EXP_API dword_t fill_pattern_dibbits(const xcolor_t* pxc_front, const xcolor_t* pxc_back, const bitmap_info_head_t* pbi, const bitmap_quad_t* pbq, byte_t* buf, dword_t max);

	EXP_API dword_t fill_gradient_dibbits(const xcolor_t* pxc_brim, const xcolor_t* pxc_core, const tchar_t* type, const bitmap_info_head_t* pbi, byte_t* buf, dword_t max);

	EXP_API dword_t fill_code128_dibbits(const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols, int bar_unit, const bitmap_info_head_t* pbi, const bitmap_quad_t* pbq, byte_t* buf, dword_t max);

	EXP_API dword_t fill_pdf417_dibbits(const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols, int unit, const bitmap_info_head_t* pbi, const bitmap_quad_t* pbq, byte_t* buf, dword_t max);

	EXP_API dword_t fill_qrcode_dibbits(const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols, int unit, const bitmap_info_head_t* pbi, const bitmap_quad_t* pbq, byte_t* buf, dword_t max);

#ifdef	__cplusplus
}
#endif


#endif /*DIB_H*/