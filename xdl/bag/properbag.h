﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc property bag document

	@module	properbag.h | interface file

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

#ifndef _PROPERBAG_H
#define _PROPERBAG_H

#include "../xdldef.h"


#ifdef	__cplusplus
extern "C" {
#endif

EXP_API int write_style_attr(const tchar_t* org_style, int slen, const tchar_t* sz_key, int klen, const tchar_t* sz_val, int vlen, tchar_t* new_style, int max);

EXP_API int read_style_attr(const tchar_t* style, int len, const tchar_t* sz_key, int klen, tchar_t* buf, int max);

EXP_API void properbag_parse_stylesheet(link_t_ptr ptr,const tchar_t* str);

EXP_API int properbag_format_stylesheet(link_t_ptr ptr,tchar_t* buf,int len);

EXP_API void properbag_write_images_attributes(link_t_ptr ptr, link_t_ptr imagelist);

EXP_API void properbag_read_images_attributes(link_t_ptr ptr, link_t_ptr imagelist);

EXP_API void properbag_write_images_item_attributes(link_t_ptr ptr, link_t_ptr imageitem);

EXP_API void properbag_read_images_item_attributes(link_t_ptr ptr, link_t_ptr imageitem);

EXP_API void properbag_write_form_attributes(link_t_ptr ptr, link_t_ptr form);

EXP_API void properbag_read_form_attributes(link_t_ptr ptr, link_t_ptr form);

EXP_API void properbag_write_field_attributes(link_t_ptr ptr, link_t_ptr flk);

EXP_API void properbag_read_field_attributes(link_t_ptr ptr, link_t_ptr flk);

EXP_API void properbag_write_grid_attributes(link_t_ptr ptr, link_t_ptr grid);

EXP_API void properbag_read_grid_attributes(link_t_ptr ptr, link_t_ptr grid);

EXP_API void properbag_write_col_attributes(link_t_ptr ptr, link_t_ptr clk);

EXP_API void properbag_read_col_attributes(link_t_ptr ptr, link_t_ptr clk);

EXP_API void properbag_write_statis_attributes(link_t_ptr ptr, link_t_ptr grid);

EXP_API void properbag_read_statis_attributes(link_t_ptr ptr, link_t_ptr grid);

EXP_API void properbag_write_gax_attributes(link_t_ptr ptr, link_t_ptr glk);

EXP_API void properbag_read_gax_attributes(link_t_ptr ptr, link_t_ptr glk);

EXP_API void properbag_write_yax_attributes(link_t_ptr ptr, link_t_ptr ylk);

EXP_API void properbag_read_yax_attributes(link_t_ptr ptr, link_t_ptr ylk);

EXP_API void properbag_write_topog_attributes(link_t_ptr ptr, link_t_ptr topog, int row, int col);

EXP_API void properbag_read_topog_attributes(link_t_ptr ptr, link_t_ptr topog);

EXP_API void properbag_write_topog_spot_attributes(link_t_ptr ptr, link_t_ptr ilk);

EXP_API void properbag_read_topog_spot_attributes(link_t_ptr ptr, link_t_ptr ilk);

EXP_API void properbag_write_rich_attributes(link_t_ptr ptr, link_t_ptr rich);

EXP_API void properbag_read_rich_attributes(link_t_ptr ptr, link_t_ptr rich);

EXP_API void properbag_write_rich_anch_attributes(link_t_ptr ptr, link_t_ptr ilk);

EXP_API void properbag_read_rich_anch_attributes(link_t_ptr ptr, link_t_ptr ilk);

EXP_API void properbag_write_dialog_attributes(link_t_ptr ptr, link_t_ptr dialog);

EXP_API void properbag_read_dialog_attributes(link_t_ptr ptr, link_t_ptr dialog);

EXP_API void properbag_write_dialog_item_attributes(link_t_ptr ptr, link_t_ptr ilk);

EXP_API void properbag_read_dialog_item_attributes(link_t_ptr ptr, link_t_ptr ilk);

EXP_API void properbag_write_diagram_attributes(link_t_ptr ptr, link_t_ptr diagram);

EXP_API void properbag_read_diagram_attributes(link_t_ptr ptr, link_t_ptr diagram);

EXP_API void properbag_write_diagram_entity_attributes(link_t_ptr ptr, link_t_ptr ilk);

EXP_API void properbag_read_diagram_entity_attributes(link_t_ptr ptr, link_t_ptr ilk);

EXP_API void properbag_write_plot_attributes(link_t_ptr ptr, link_t_ptr plot);

EXP_API void properbag_read_plot_attributes(link_t_ptr ptr, link_t_ptr plot);

#ifdef	__cplusplus
}
#endif


#endif //PROPERBAG_H