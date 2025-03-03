﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc statis document

	@module	statisdoc.h | interface file

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

#ifndef _STATISDOC_H
#define _STATISDOC_H

#include "../xdldef.h"


/************************************************Properties***************************************************************************/

/*
@PROPER name: string.
@GET get_statis_name: get the statis name.
*/
#define get_statis_name_ptr(ptr)							get_dom_node_attr_ptr(ptr,ATTR_NAME,-1)
/*
@PROPER name: string.
@SET set_statis_name_ptr: set the statis name.
*/
#define set_statis_name(ptr,token)						set_dom_node_attr(ptr,ATTR_NAME,-1,token,-1)
/*
@PROPER id: string.
@GET set_statis_name: get the statis identifier.
*/
#define get_statis_id_ptr(ptr)							get_dom_node_attr_ptr(ptr,ATTR_ID,-1)
/*
@PROPER id: string.
@SET get_statis_name_ptr: set the statis identifier.
*/
#define set_statis_id(ptr,token)							set_dom_node_attr(ptr,ATTR_ID,-1,token,-1)
/*
@PROPER title: string.
@GET get_statis_title_ptr: get the statis title.
*/
#define get_statis_title_ptr(ptr)						get_dom_node_attr_ptr(ptr,ATTR_TITLE,-1)
/*
@PROPER title: string.
@SET set_statis_title: set the statis title.
*/
#define set_statis_title(ptr,token)						set_dom_node_attr(ptr,ATTR_TITLE,-1,token,-1)
/*
@PROPER style: string.
@GET get_statis_style_ptr: get the statis style.
*/
#define get_statis_style_ptr(ptr)						get_dom_node_attr_ptr(ptr,ATTR_STYLE,-1)
/*
@PROPER style: string.
@SET set_statis_style: set the statis style.
*/
#define set_statis_style(ptr,token)						set_dom_node_attr(ptr,ATTR_STYLE,-1,token,-1)
/*
@PROPER width: float.
@GET get_statis_width: get the statis width.
*/
#define get_statis_width(ptr)							get_dom_node_attr_float(ptr,ATTR_WIDTH)
/*
@PROPER width: float.
@SET set_statis_width: set the statis width.
*/
#define set_statis_width(ptr,n)							set_dom_node_attr_float(ptr,ATTR_WIDTH,n)
/*
@PROPER height: float.
@GET get_statis_height: get the statis height.
*/
#define get_statis_height(ptr)							get_dom_node_attr_float(ptr,ATTR_HEIGHT)
/*
@PROPER height: float.
@SET set_statis_height: set the statis height.
*/
#define set_statis_height(ptr,n)							set_dom_node_attr_float(ptr,ATTR_HEIGHT,n)
/*
@PROPER height: float.
@GET get_statis_title_height: get the statis title height.
*/
#define get_statis_title_height(ptr)						get_dom_node_attr_float(ptr,ATTR_TITLE_HEIGHT)
/*
@PROPER height: float.
@SET set_statis_title_height: set the statis title height.
*/
#define set_statis_title_height(ptr,n)					set_dom_node_attr_float(ptr,ATTR_TITLE_HEIGHT,n)
/*
@PROPER yaxHeight: float.
@GET get_statis_yaxbar_height: get the statis yax bar height.
*/
#define get_statis_yaxbar_height(ptr)					get_dom_node_attr_float(ptr,ATTR_YAXBAR_HEIGHT)
/*
@PROPER yaxHeight: float.
@SET set_statis_yaxbar_height: set the statis yax bar height.
*/
#define set_statis_yaxbar_height(ptr,n)					set_dom_node_attr_float(ptr,ATTR_YAXBAR_HEIGHT,n)
/*
@PROPER yaxWidth: float.
@GET get_statis_yaxbar_width: get the statis yax bar width.
*/
#define get_statis_yaxbar_width(ptr)						get_dom_node_attr_float(ptr,ATTR_YAXBAR_WIDTH)
/*
@PROPER yaxWidth: float.
@SET set_statis_yaxbar_width: set the statis yax bar width.
*/
#define set_statis_yaxbar_width(ptr,n)					set_dom_node_attr_float(ptr,ATTR_YAXBAR_WIDTH,n)
/*
@PROPER xaxWidth: float.
@GET get_statis_xaxbar_width: get the statis xax bar width.
*/
#define get_statis_xaxbar_width(ptr)						get_dom_node_attr_float(ptr,ATTR_XAXBAR_WIDTH)
/*
@PROPER xaxWidth: float.
@SET set_statis_xaxbar_width: set the statis xax bar width.
*/
#define set_statis_xaxbar_width(ptr,n)					set_dom_node_attr_float(ptr,ATTR_XAXBAR_WIDTH,n)
/*
@PROPER xaxHeight: float.
@GET get_statis_xaxbar_height: get the statis xax bar height.
*/
#define get_statis_xaxbar_height(ptr)					get_dom_node_attr_float(ptr,ATTR_XAXBAR_HEIGHT)
/*
@PROPER xaxHeight: float.
@SET set_statis_xaxbar_height: set the statis xax bar height.
*/
#define set_statis_xaxbar_height(ptr,n)					set_dom_node_attr_float(ptr,ATTR_XAXBAR_HEIGHT,n)
/*
@PROPER printing: string.
@SET set_statis_printing: set the statis printing oritation.
*/
#define set_statis_printing(ptr,val)					set_dom_node_attr(ptr,ATTR_PRINTING,-1,val,-1)
/*
@PROPER printing: string.
@SET get_statis_printing: get the statis printing oritation.
*/
#define get_statis_printing_ptr(ptr)					get_dom_node_attr_ptr(ptr,ATTR_PRINTING,-1)
/*
@PROPER showCheck: boolean.
@GET get_statis_showcheck: get the statis show check box.
*/
#define get_statis_showcheck(ptr)						get_dom_node_attr_boolean(ptr,ATTR_SHOWCHECK)
/*
@PROPER showCheck: boolean.
@SET set_statis_showcheck: set the statis show check box.
*/
#define set_statis_showcheck(ptr,b)						set_dom_node_attr_boolean(ptr,ATTR_SHOWCHECK,b)
/*
@PROPER showSummary: boolean.
@GET get_statis_showsum: get the statis show summary bar.
*/
#define get_statis_showsum(ptr)							get_dom_node_attr_boolean(ptr,ATTR_SHOWSUM)
/*
@PROPER showSummary: boolean.
@SET set_statis_showsum: set the statis show summary bar.
*/
#define set_statis_showsum(ptr,b)						set_dom_node_attr_boolean(ptr,ATTR_SHOWSUM,b)
/*
@PROPER xaxIs: boolean.
@GET get_statis_xaxis_ptr: get the statis xax is.
*/
#define get_statis_xaxis_ptr(ptr)						get_dom_node_attr_ptr(ptr,ATTR_XAXIS,-1)
/*
@PROPER xaxIs: boolean.
@SET set_statis_xaxis: set the statis xax is.
*/
#define set_statis_xaxis(ptr,token)						set_dom_node_attr(ptr,ATTR_XAXIS,-1,token,-1)
/*
@PROPER xaxDataType: boolean.
@GET get_statis_xaxdt_ptr: get the statis xax data type.
*/
#define get_statis_xaxdt_ptr(ptr)						get_dom_node_attr_ptr(ptr,ATTR_XAXDT,-1)
/*
@PROPER xaxDataType: boolean.
@SET set_statis_xaxdt: set the statis xax data type.
*/
#define set_statis_xaxdt(ptr,token)						set_dom_node_attr(ptr,ATTR_XAXDT,-1,token,-1)
/*
@PROPER xaxFormat: boolean.
@GET get_statis_xaxfmt_ptr: get the statis xax format.
*/
#define get_statis_xaxfmt_ptr(ptr)						get_dom_node_attr_ptr(ptr,ATTR_XAXFMT,-1)
/*
@PROPER xaxFormat: boolean.
@SET set_statis_xaxfmt: set the statis xax format.
*/
#define set_statis_xaxfmt(ptr,token)						set_dom_node_attr(ptr,ATTR_XAXFMT,-1,token,-1)
/*
@PROPER xaxWrap: boolean.
@GET get_statis_xaxwrp: get the statis xax wrap drawing.
*/
#define get_statis_xaxwrp(ptr)							get_dom_node_attr_boolean(ptr,ATTR_XAXWRP)
/*
@PROPER xaxWrap: boolean.
@SET set_statis_xaxwrp: set the statis xax wrap drawing.
*/
#define set_statis_xaxwrp(ptr,b)							set_dom_node_attr_boolean(ptr,ATTR_XAXWRP,b)
/*
@PROPER name: string.
@SET set_gax_name: set the gax name.
*/
#define set_gax_name(glk,val)							set_dom_node_attr(glk,ATTR_NAME,-1,val,-1)
/*
@PROPER name: string.
@GET get_gax_name_ptr: get the gax name.
*/
#define get_gax_name_ptr(glk)							get_dom_node_attr_ptr(glk,ATTR_NAME,-1)
/*
@PROPER title: string.
@SET set_gax_title: set the gax title.
*/
#define set_gax_title(glk,val)							set_dom_node_attr(glk,ATTR_TITLE,-1,val,-1)
/*
@PROPER title: string.
@GET get_gax_title_ptr: get the gax title.
*/
#define get_gax_title_ptr(glk)							get_dom_node_attr_ptr(glk,ATTR_TITLE,-1)
/*
@PROPER statisType: string.
@GET get_gax_statis_type_ptr: get the gax statis type.
*/
#define get_gax_statis_type_ptr(glk)						get_dom_node_attr_ptr(glk,ATTR_STATIS_TYPE,-1)
/*
@PROPER statisType: string.
@SET set_gax_statis_type: set the gax statis type.
*/
#define set_gax_statis_type(glk,token)					set_dom_node_attr(glk,ATTR_STATIS_TYPE,-1,token,-1)
/*
@PROPER step: numeric.
@GET get_gax_step: get the gax step.
*/
#define get_gax_step(glk)								get_dom_node_attr_numeric(glk,ATTR_GAX_STEP)
/*
@PROPER step: numeric.
@SET set_gax_step: set the gax step.
*/
#define set_gax_step(glk,n)								set_dom_node_attr_numeric(glk,ATTR_GAX_STEP,n)
/*
@PROPER middle: numeric.
@GET get_gax_midd: get the gax middle.
*/
#define get_gax_midd(glk)								get_dom_node_attr_numeric(glk,ATTR_GAX_MIDD)
/*
@PROPER middle: numeric.
@SET set_gax_midd: set the gax middle.
*/
#define set_gax_midd(glk,n)								set_dom_node_attr_numeric(glk,ATTR_GAX_MIDD,n)
/*
@PROPER name: string.
@SET set_yax_name: set the yax name.
*/
#define set_yax_name(ylk,val)							set_dom_node_attr(ylk,ATTR_NAME,-1,val,-1)
/*
@PROPER name: string.
@GET get_yax_name_ptr: get the yax name.
*/
#define get_yax_name_ptr(ylk)							get_dom_node_attr_ptr(ylk,ATTR_NAME,-1)
/*
@PROPER id: string.
@SET set_yax_id: set the yax identifier.
*/
#define set_yax_id(ylk,val)								set_dom_node_attr(ylk,ATTR_ID,-1,val,-1)
/*
@PROPER id: string.
@GET get_yax_id_ptr: get the yax identifier.
*/
#define get_yax_id_ptr(ylk)								get_dom_node_attr_ptr(ylk,ATTR_ID,-1)
/*
@PROPER title: string.
@SET set_yax_title: set the yax title.
*/
#define set_yax_title(ylk,val)							set_dom_node_attr(ylk,ATTR_TITLE,-1,val,-1)
/*
@PROPER title: string.
@GET get_yax_title_ptr: get the yax title.
*/
#define get_yax_title_ptr(ylk)							get_dom_node_attr_ptr(ylk,ATTR_TITLE,-1)
/*
@PROPER group: string.
@SET set_yax_group: set the yax group.
*/
#define set_yax_group(ylk,val)							set_dom_node_attr(ylk,ATTR_GROUP,-1,val,-1)
/*
@PROPER group: string.
@GET get_yax_group_ptr: get the yax group.
*/
#define get_yax_group_ptr(ylk)							get_dom_node_attr_ptr(ylk,ATTR_GROUP,-1)
/*
@PROPER lineCap: string.
@GET get_yax_line_cap_ptr: get the yax line cap.
*/
#define get_yax_line_cap_ptr(ylk)						get_dom_node_attr_ptr(ylk,ATTR_LINE_CAP,-1)
/*
@PROPER lineCap: string.
@SET set_yax_line_cap: set the yax line cap.
*/
#define set_yax_line_cap(ylk,token)						set_dom_node_attr(ylk,ATTR_LINE_CAP,-1,token,-1)
/*
@PROPER dataLen: integer.
@GET get_yax_data_len: get the yax line cap.
*/
#define get_yax_data_len(ylk)							get_dom_node_attr_integer(ylk,ATTR_DATA_LEN)
/*
@PROPER dataLen: integer.
@SET set_yax_data_len: set the yax line cap.
*/
#define set_yax_data_len(ylk,n)							set_dom_node_attr_integer(ylk,ATTR_DATA_LEN,n)
/*
@PROPER dataDig: integer.
@GET get_yax_data_dig: get the yax data digits.
*/
#define get_yax_data_dig(ylk)							get_dom_node_attr_integer(ylk,ATTR_DATA_DIG)
/*
@PROPER dataDig: integer.
@SET set_yax_data_dig: set the yax data digits.
*/
#define set_yax_data_dig(ylk,n)							set_dom_node_attr_integer(ylk,ATTR_DATA_DIG,n)
/*
@PROPER zeroNull: boolean.
@GET get_yax_zeronull: get the yax data digits.
*/
#define get_yax_zeronull(ylk)							get_dom_node_attr_boolean(ylk,ATTR_ZERONULL)
/*
@PROPER zeroNull: boolean.
@SET set_yax_zeronull: set the yax data digits.
*/
#define set_yax_zeronull(ylk,b)							set_dom_node_attr_boolean(ylk,ATTR_ZERONULL,b)
/*
@PROPER sortable: boolean.
@GET get_yax_sortable: get the yax sortable.
*/
#define get_yax_sortable(ylk)							get_dom_node_attr_boolean(ylk,ATTR_SORTABLE)
/*
@PROPER sortable: boolean.
@SET set_yax_sortable: set the yax sortable.
*/
#define set_yax_sortable(ylk,b)							set_dom_node_attr_boolean(ylk,ATTR_SORTABLE,b)
/*
@PROPER color: string.
@SET set_yax_color: set the yax color token.
*/
#define set_yax_color(ylk,val)							set_dom_node_attr(ylk,ATTR_COLOR,-1,val,-1)
/*
@PROPER color: string.
@GET get_yax_color_ptr: get the yax color token.
*/
#define get_yax_color_ptr(ylk)							get_dom_node_attr_ptr(ylk,ATTR_COLOR,-1)
/*
@PROPER image: string.
@GET get_yax_image_ptr: get the yax image name.
*/
#define get_yax_image_ptr(ylk)							get_dom_node_attr_ptr(ylk,ATTR_IMAGE,-1)
/*
@PROPER image: string.
@SET set_yax_image: set the yax image name.
*/
#define set_yax_image(ylk,token)						set_dom_node_attr(ylk,ATTR_IMAGE,-1,token,-1)

#define get_xax_attr_table(xlk)							get_dom_node_attr_table(xlk)
/*
@PROPER text: string.
@SET set_xax_text: set the xax text.
*/
#define set_xax_text(xlk,val)							set_dom_node_text(xlk,val,-1)
/*
@PROPER text: string.
@GET get_xax_text_ptr: get the xax text.
*/
#define get_xax_text_ptr(xlk)							get_dom_node_text_ptr(xlk)
/*
@PROPER name: string.
@SET set_xax_name: set the xax name.
*/
#define set_xax_name(xlk,val)							set_dom_node_attr(xlk,ATTR_NAME,-1,val,-1)
/*
@PROPER name: string.
@GET get_xax_name_ptr: get the xax name.
*/
#define get_xax_name_ptr(xlk)							get_dom_node_attr_ptr(xlk,ATTR_NAME,-1)

/*
@PROPER images: document.
@SET set_statis_images: set the statis images reference.
*/
#define set_statis_images(ptr,images)					set_dom_node_images(ptr,images)
/*
@PROPER images: document.
@GET get_statis_images: get the statis image reference.
*/
#define get_statis_images(ptr)							get_dom_node_images(ptr)
/*
@PROPER design: boolean.
@SET set_statis_design: set the statis is design mode.
*/
#define set_statis_design(ptr,b)							set_dom_node_mask_check(ptr,MSK_DESIGN,b) 
/*
@PROPER design: boolean.
@GET statis_is_design: get the statis is design mode.
*/
#define statis_is_design(ptr)							get_dom_node_mask_check(ptr,MSK_DESIGN)
/*
@PROPER checked: boolean.
@SET set_xax_checked: set the xax is checked.
*/
#define set_xax_checked(xlk,check)						set_dom_node_mask_check(xlk,MSK_CHECKED,check)
/*
@PROPER checked: boolean.
@GET get_xax_checked: get the xsx is checked.
*/
#define get_xax_checked(xlk)							get_dom_node_mask_check(xlk,MSK_CHECKED)
/*
@PROPER locked: boolean.
@SET set_xax_locked: set the xax is locked.
*/
#define set_xax_locked(xlk,c)							set_dom_node_mask_check(xlk,MSK_LOCKED,c) 
/*
@PROPER locked: boolean.
@GET get_xax_locked: get the xsx is locked.
*/
#define get_xax_locked(xlk)								get_dom_node_mask_check(xlk,MSK_LOCKED)
/*
@PROPER selected: boolean.
@SET set_yax_selected: set the xax is selected.
*/
#define set_yax_selected(ylk,check)						set_dom_node_mask_check(ylk,MSK_CHECKED,check)
/*
@PROPER selected: boolean.
@GET get_yax_selected: get the xsx is selected.
*/
#define get_yax_selected(ylk)							get_dom_node_mask_check(ylk,MSK_CHECKED)
/*
@PROPER state: integer.
@SET set_xax_state: set the xax state.
*/
#define set_xax_state(xlk,c)							set_dom_node_mask(xlk,(get_dom_node_mask(xlk) & 0xFFFFFFF0) | c)
/*
@PROPER state: integer.
@GET get_xax_state: get the xsx state.
*/
#define get_xax_state(xlk)								(get_dom_node_mask(xlk) & 0x0000000F)


#ifdef	__cplusplus
extern "C" {
#endif

/************************************************Functions***************************************************************************/

/*
@FUNCTION create_statis_doc: create a statis document.
@RETURN link_t_ptr: return the statis document link component.
*/
EXP_API link_t_ptr create_statis_doc(void);

/*
@FUNCTION destroy_statis_doc: destroy a statis document.
@INPUT link_t_ptr ptr: the statis document link component.
@RETURN void: none.
*/
EXP_API void destroy_statis_doc(link_t_ptr ptr);

/*
@FUNCTION clear_statis_doc: clear a statis document.
@INPUT link_t_ptr ptr: the statis document link component.
@RETURN void: none.
*/
EXP_API void clear_statis_doc(link_t_ptr ptr);

/*
@FUNCTION clear_statis_xaxset: clear the statis xax set.
@INPUT link_t_ptr ptr: the statis document link component.
@RETURN void: none.
*/
EXP_API void clear_statis_xaxset(link_t_ptr ptr);

/*
@FUNCTION clear_statis_gaxset: clear the statis gax set.
@INPUT link_t_ptr ptr: the statis document link component.
@RETURN void: none.
*/
EXP_API void clear_statis_gaxset(link_t_ptr ptr);

/*
@FUNCTION clear_statis_yaxset: clear the statis yax set.
@INPUT link_t_ptr ptr: the statis document link component.
@RETURN void: none.
*/
EXP_API void clear_statis_yaxset(link_t_ptr ptr);

/*
@FUNCTION merge_statis_yaxset: merge source yax set to destination yax set.
@INPUT link_t_ptr ptr_dst: the destination yax link component.
@INPUT link_t_ptr ptr_src: the source yax link component.
@RETURN void: none.
*/
EXP_API void merge_statis_yaxset(link_t_ptr ptr_dst, link_t_ptr ptr_src);

/*
@FUNCTION merge_statis_xaxset: merge source xax set to destination xax set.
@INPUT link_t_ptr ptr_dst: the destination xax link component.
@INPUT link_t_ptr ptr_src: the source xax link component.
@RETURN void: none.
*/
EXP_API void merge_statis_xaxset(link_t_ptr ptr_dst, link_t_ptr ptr_src);

/*
@FUNCTION is_statis_doc: test is statis document.
@INPUT link_t_ptr ptr: the statis link component.
@RETURN bool_t: return nonzero for being a statis document, otherwise return zero.
*/
EXP_API bool_t is_statis_doc(link_t_ptr ptr);

/*
@FUNCTION is_statis_xax: test is statis xax.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr xlk: the xax link component.
@RETURN bool_t: return nonzero for being a xax of statis, otherwise return zero.
*/
EXP_API bool_t is_statis_xax(link_t_ptr ptr,link_t_ptr xlk);

/*
@FUNCTION is_statis_yax: test is statis yax.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr ylk: the yax link component.
@RETURN bool_t: return nonzero for being a yax of statis, otherwise return zero.
*/
EXP_API bool_t is_statis_yax(link_t_ptr ptr,link_t_ptr ylk);

/*
@FUNCTION is_statis_gax: test is statis gax.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr glk: the gax link component.
@RETURN bool_t: return nonzero for being a gax of statis, otherwise return zero.
*/
EXP_API bool_t is_statis_gax(link_t_ptr ptr, link_t_ptr glk);

/*
@FUNCTION insert_gax: add a new gax into statis.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr pos: the gax link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return the new gax link component.
*/
EXP_API link_t_ptr insert_gax(link_t_ptr ptr, link_t_ptr pos);

/*
@FUNCTION delete_gax: delete a gax.
@INPUT link_t_ptr glk: the gax link component.
@RETURN void: none.
*/
EXP_API void delete_gax(link_t_ptr glk);

/*
@FUNCTION get_statis_gaxset: get the statis gax set.
@INPUT link_t_ptr ptr: the statis link component.
@RETURN link_t_ptr: return the gax set link component.
*/
EXP_API link_t_ptr get_statis_gaxset(link_t_ptr ptr);

/*
@FUNCTION get_next_gax: get the next gax.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr pos: the gax link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return the gax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_next_gax(link_t_ptr ptr, link_t_ptr pos);

/*
@FUNCTION get_prev_gax: get the previous gax.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr pos: the gax link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return the gax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_prev_gax(link_t_ptr ptr, link_t_ptr pos);

/*
@FUNCTION get_gax: find the gax by name.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT const tchar_t* gname: the gax name token.
@RETURN link_t_ptr: return the gax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_gax(link_t_ptr ptr, const tchar_t* gname);

/*
@FUNCTION get_gax_count: counting the gaxs in statis.
@INPUT link_t_ptr ptr: the statis link component.
@RETURN int: return the number of gaxs.
*/
EXP_API int get_gax_count(link_t_ptr ptr);

/*
@FUNCTION insert_yax: add a new yax into statis.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr pos: the yax link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return the new yax link component.
*/
EXP_API link_t_ptr insert_yax(link_t_ptr ptr, link_t_ptr pos);

/*
@FUNCTION delete_yax: delete a yax.
@INPUT link_t_ptr ylk: the yax link component.
@RETURN void: none.
*/
EXP_API void delete_yax(link_t_ptr ylk);

/*
@FUNCTION get_statis_yaxset: get statis yax set.
@INPUT link_t_ptr ptr: the statis link component.
@RETURN link_t_ptr: return yax set link component.
*/
EXP_API link_t_ptr get_statis_yaxset(link_t_ptr ptr);

/*
@FUNCTION get_yax_count: counting yaxs in statis
@INPUT link_t_ptr ptr: the statis link component.
@RETURN int: return the number of yaxs.
*/
EXP_API int get_yax_count(link_t_ptr ptr);

/*
@FUNCTION get_yax_selected_count: counting selected yaxs in statis
@INPUT link_t_ptr ptr: the statis link component.
@RETURN int: return the number of yaxs.
*/
EXP_API int get_yax_selected_count(link_t_ptr ptr);

/*
@FUNCTION get_next_yax: get the next statis yax.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr pos: the yax link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return yax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_next_yax(link_t_ptr ptr,link_t_ptr pos);

/*
@FUNCTION get_prev_yax: get the previous statis yax.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr pos: the yax link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return yax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_prev_yax(link_t_ptr ptr,link_t_ptr pos);

/*
@FUNCTION get_yax_at: get the statis yax at position.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT int index: the zero based position.
@RETURN link_t_ptr: return yax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_yax_at(link_t_ptr ptr, int index);

/*
@FUNCTION get_yax: find statis yax by name.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT const tchar_t* yname: the yax name token.
@RETURN link_t_ptr: return yax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_yax(link_t_ptr ptr, const tchar_t* yname);

/*
@FUNCTION get_xax: find statis xax by name.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT const tchar_t* xname: the xax name token.
@RETURN link_t_ptr: return xax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_yax_by_id(link_t_ptr ptr, const tchar_t* cid);

/*
@FUNCTION get_yax_gax: get gax bind to the yax.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr ylk: the yax link component.
@RETURN link_t_ptr: return gax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_yax_gax(link_t_ptr ptr, link_t_ptr ylk);

/*
@FUNCTION get_statis_xaxset: get xax set.
@INPUT link_t_ptr ptr: the statis link component.
@RETURN link_t_ptr: return gax set link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_statis_xaxset(link_t_ptr ptr);

/*
@FUNCTION insert_xax: add a xax to statis.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr pos: the xax link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return the new xax link component.
*/
EXP_API link_t_ptr insert_xax(link_t_ptr ptr, link_t_ptr pos);

/*
@FUNCTION get_xax_count: counting the xaxs in statis.
@INPUT link_t_ptr ptr: the statis link component.
@RETURN int: return the number of xaxs.
*/
EXP_API int get_xax_count(link_t_ptr ptr);

/*
@FUNCTION get_xax_checked_count: counting the checked xaxs in statis.
@INPUT link_t_ptr ptr: the statis link component.
@RETURN int: return the number of xaxs.
*/
EXP_API int get_xax_checked_count(link_t_ptr ptr);

/*
@FUNCTION get_xax_at: get the xax at position.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT int pos: the zero based position.
@RETURN link_t_ptr: return the xax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_xax_at(link_t_ptr ptr, int pos);

/*
@FUNCTION delete_xax: delete the xax.
@INPUT link_t_ptr xlk: the xax link component.
@RETURN void: none.
*/
EXP_API void delete_xax(link_t_ptr xlk);

/*
@FUNCTION get_next_xax: get the next xax.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr xlk: the xax link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return xax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_next_xax(link_t_ptr ptr,link_t_ptr pos);

/*
@FUNCTION get_prev_xax: get the previous xax.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr xlk: the xax link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return xax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_prev_xax(link_t_ptr ptr, link_t_ptr xlk);

/*
@FUNCTION get_xax: find statis xax by name.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT const tchar_t* xname: the xax name token.
@RETURN link_t_ptr: return xax link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_xax(link_t_ptr ptr, const tchar_t* xname);

/*
@FUNCTION get_xax_storage_ptr: find the xax storage by key.
@INPUT link_t_ptr xlk: the xax link component.
@INPUT const tchar_t* key: the key token.
@RETURN const tchar_t*: return the storage token if exists, otherwise return NULL.
*/
EXP_API const tchar_t* get_xax_storage_ptr(link_t_ptr xlk, const tchar_t* key);

/*
@FUNCTION set_xax_storage: add a storage to xax.
@INPUT link_t_ptr xlk: the xax link component.
@INPUT const tchar_t* key: the key token.
@INPUT const tchar_t* val: the value token.
@RETURN void: none.
*/
EXP_API void set_xax_storage(link_t_ptr xlk, const tchar_t* key, const tchar_t* val);

/*
@FUNCTION get_update_xax_count: counting the update state xaxs.
@INPUT link_t_ptr xlk: the xax link component.
@RETURN int: return the number of xaxs.
*/
EXP_API int get_update_xax_count(link_t_ptr ptr);

/*
@FUNCTION refresh_statis_xaxset: clear the xax set state.
@INPUT link_t_ptr ptr: the statis link component.
@RETURN void: none.
*/
EXP_API void refresh_statis_xaxset(link_t_ptr ptr);

/*
@FUNCTION set_coor_numeric: set the coor numeric.
@INPUT link_t_ptr xlk: the xax link component.
@INPUT link_t_ptr ylk: the yax link component.
@INPUT double dbl: the numeric.
@RETURN void: none.
*/
EXP_API void set_coor_numeric(link_t_ptr xlk, link_t_ptr ylk, double dbl);

/*
@FUNCTION get_coor_numeric: get the coor numeric.
@INPUT link_t_ptr xlk: the xax link component.
@INPUT link_t_ptr ylk: the yax link component.
@RETURN double: return the coor numeric.
*/
EXP_API double get_coor_numeric(link_t_ptr xlk,link_t_ptr ylk);

/*
@FUNCTION set_coor_text: set the coor text.
@INPUT link_t_ptr xlk: the xax link component.
@INPUT link_t_ptr ylk: the yax link component.
@INPUT const tchar_t* token: the text string token.
@INPUT int len: the length of text in characters.
@RETURN void: none.
*/
EXP_API void set_coor_text(link_t_ptr xlk, link_t_ptr ylk, const tchar_t* token, int len);

/*
@FUNCTION get_coor_text_ptr: get the coor text token.
@INPUT link_t_ptr xlk: the xax link component.
@INPUT link_t_ptr ylk: the yax link component.
@RETURN const tchar_t*: return the text token.
*/
EXP_API const tchar_t* get_coor_text_ptr(link_t_ptr xlk, link_t_ptr ylk);

/*
@FUNCTION get_coor_text: copy the coor text token.
@INPUT link_t_ptr xlk: the xax link component.
@INPUT link_t_ptr ylk: the yax link component.
@OUTPUT tchar_t* buf: the string buffer for returning coor text.
@INPUT int max: the string buffer size in characters.
@RETURN int: return the characters copied.
*/
EXP_API int get_coor_text(link_t_ptr xlk, link_t_ptr ylk, tchar_t* buf, int max);

/*
@FUNCTION get_coor_storage_ptr: get the coor storage value by key.
@INPUT link_t_ptr xlk: the xax link component.
@INPUT link_t_ptr ylk: the yax link component.
@INPUT const tchar_t* key: the key token.
@RETURN const tchar_t*: return the storage value token.
*/
EXP_API const tchar_t* get_coor_storage_ptr(link_t_ptr xlk, link_t_ptr ylk, const tchar_t* key);

/*
@FUNCTION set_coor_storage: add a storage to coor.
@INPUT link_t_ptr xlk: the xax link component.
@INPUT link_t_ptr ylk: the yax link component.
@INPUT const tchar_t* key: the key token.
@INPUT const tchar_t* val: the value token.
@RETURN void: none.
*/
EXP_API void set_coor_storage(link_t_ptr xlk, link_t_ptr ylk, const tchar_t* key, const tchar_t* val);

/*
@FUNCTION set_coor_dirty: set the coor state.
@INPUT link_t_ptr xlk: the xax link component.
@INPUT link_t_ptr ylk: the yax link component.
@INPUT bool_t b: nonzero for dirty, zero for clean.
@RETURN void: none.
*/
EXP_API void set_coor_dirty(link_t_ptr rlk, link_t_ptr clk, bool_t b);

/*
@FUNCTION get_coor_dirty: get the coor state.
@INPUT link_t_ptr xlk: the xax link component.
@INPUT link_t_ptr ylk: the yax link component.
@RETURN bool_t: return nonzero for dirty, zero for clean..
*/
EXP_API bool_t get_coor_dirty(link_t_ptr rlk, link_t_ptr clk);

/*
@FUNCTION set_xax_clean: set xax state to clean.
@INPUT link_t_ptr xlk: the xax link component.
@RETURN void: none.
*/
EXP_API void set_xax_clean(link_t_ptr rlk);

/*
@FUNCTION set_xax_dirty: set xax state to dirty.
@INPUT link_t_ptr xlk: the xax link component.
@RETURN void: none.
*/
EXP_API void set_xax_dirty(link_t_ptr rlk);

/*
@FUNCTION calc_statis_gax_base: calcing the statis gax base line.
@INPUT link_t_ptr ptr: the statis link component.
@INPUT link_t_ptr glk: the gax link component.
@OUTPUT float* pmidd: for return middle line value.
@OUTPUT float* pstep: for return step value.
@RETURN void: none.
*/
EXP_API void calc_statis_gax_base(link_t_ptr ptr, link_t_ptr glk, float* pmidd, float* pstep);

#ifdef	__cplusplus
}
#endif


#endif //STATISDOC_H