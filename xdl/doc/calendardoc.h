﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc calendar document

	@module	calendardoc.h | interface file

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

#ifndef _CALENDARDOC_H
#define _CALENDARDOC_H

#include "../xdldef.h"


/*******************************************serial enable attributes********************************************/
#define set_calendar_name(ptr,token)						set_dom_node_attr(ptr,ATTR_NAME,-1,token,-1)

#define get_calendar_name_ptr(ptr)							get_dom_node_attr_ptr(ptr,ATTR_NAME,-1)

#define set_calendar_id(ptr,token)							set_dom_node_attr(ptr,ATTR_ID,-1,token,-1)

#define get_calendar_id_ptr(ptr)							get_dom_node_attr_ptr(ptr,ATTR_ID,-1)

#define set_calendar_style(ptr,token)						set_dom_node_attr(ptr,ATTR_STYLE,-1,token,-1)

#define get_calendar_style_ptr(ptr)							get_dom_node_attr_ptr(ptr,ATTR_STYLE,-1)

#define get_calendar_width(ptr)								get_dom_node_attr_float(ptr,ATTR_WIDTH)

#define set_calendar_width(ptr,n)							set_dom_node_attr_float(ptr,ATTR_WIDTH,n)

#define get_calendar_height(ptr)							get_dom_node_attr_float(ptr,ATTR_HEIGHT)

#define set_calendar_height(ptr,n)							set_dom_node_attr_float(ptr,ATTR_HEIGHT,n)

#define get_calendar_title_height(ptr)						get_dom_node_attr_float(ptr,ATTR_TITLE_HEIGHT)

#define set_calendar_title_height(ptr,n)					set_dom_node_attr_float(ptr,ATTR_TITLE_HEIGHT,n)

#define set_calendar_daily(ptr,token)						set_dom_node_attr(ptr,ATTR_DAILY,-1,token,-1)

#define get_calendar_daily_ptr(ptr)							get_dom_node_attr_ptr(ptr,ATTR_DAILY,-1)

#define set_calendar_today(ptr,token)						set_dom_node_attr(ptr,ATTR_TODAY,-1,token,-1)

#define get_calendar_today_ptr(ptr)							get_dom_node_attr_ptr(ptr,ATTR_TODAY,-1)

#define set_calendar_daily_name(ilk,token)					set_dom_node_name(ilk,token,-1)

#define get_calendar_daily_name_ptr(ilk)					get_dom_node_name_ptr(ilk)

#define set_calendar_daily_earliest(ilk,token)				set_dom_node_attr(ilk,ATTR_EARLIEST,-1,token,-1)

#define get_calendar_daily_earliest_ptr(ilk)				get_dom_node_attr_ptr(ilk,ATTR_EARLIEST,-1)

#define set_calendar_daily_latest(ilk,token)				set_dom_node_attr(ilk,ATTR_LATEST,-1,token,-1)

#define get_calendar_daily_latest_ptr(ilk)					get_dom_node_attr_ptr(ilk,ATTR_LATEST,-1)

#define set_calendar_daily_text(ilk,token,len)				set_dom_node_text(ilk,token,len)

#define get_calendar_daily_text_ptr(ilk)					get_dom_node_text_ptr(ilk)

#define set_calendar_daily_style(ilk,token)					set_dom_node_attr(ilk,ATTR_STYLE,-1,token,-1)

#define get_calendar_daily_style_ptr(ilk)					get_dom_node_attr_ptr(ilk,ATTR_STYLE,-1)

/**********************************************************************************************************/
#define set_calendar_daily_delta(ilk,ul)					set_dom_node_delta(ilk,(vword_t)ul)

#define get_calendar_daily_delta(ilk)						get_dom_node_delta(ilk)

#define set_calendar_daily_selected(flk,b)					set_dom_node_mask_check(flk,MSK_CHECKED,b)

#define get_calendar_daily_selected(flk)					get_dom_node_mask_check(flk,MSK_CHECKED) 

/*********************************************************************************************************/
#ifdef	__cplusplus
extern "C" {
#endif

EXP_API link_t_ptr create_calendar_doc(void);

EXP_API void destroy_calendar_doc(link_t_ptr ptr);

EXP_API void clear_calendar_doc(link_t_ptr ptr);

EXP_API bool_t is_calendar_doc(link_t_ptr ptr);

EXP_API bool_t is_calendar_daily(link_t_ptr ptr, link_t_ptr ilk);

EXP_API void reset_calendar_taborder(link_t_ptr ptr);

EXP_API link_t_ptr get_calendar_dailyset(link_t_ptr ptr);

EXP_API link_t_ptr insert_calendar_daily(link_t_ptr ptr, const tchar_t* sz_today);

EXP_API link_t_ptr get_calendar_next_daily(link_t_ptr ptr,link_t_ptr pos);

EXP_API link_t_ptr get_calendar_prev_daily(link_t_ptr ptr,link_t_ptr pos);

EXP_API link_t_ptr get_calendar_daily(link_t_ptr ptr, const tchar_t* sz_today);

EXP_API int get_calendar_daily_count(link_t_ptr ptr);

EXP_API int get_calendar_daily_count_by_today(link_t_ptr ptr, const tchar_t* sz_today);

EXP_API int get_calendar_daily_selected_count(link_t_ptr ptr);

EXP_API void delete_calendar_daily(link_t_ptr ilk);


#ifdef	__cplusplus
}
#endif


#endif //CALENDARDOC_H