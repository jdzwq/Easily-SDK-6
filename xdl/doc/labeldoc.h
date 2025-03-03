﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc label document

	@module	labeldoc.h | interface file

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

#ifndef _LABELDOC_H
#define _LABELDOC_H

#include "../xdldef.h"


/************************************************Properties***************************************************************************/

/*
@PROPER name: string.
@GET get_label_name_ptr: get the label name.
*/
#define get_label_name_ptr(ptr)								get_dom_node_attr_ptr(ptr,ATTR_NAME,-1)
/*
@PROPER name: string.
@SET set_label_name: set the label name.
*/
#define set_label_name(ptr,token)							set_dom_node_attr(ptr,ATTR_NAME,-1,token,-1)
/*
@PROPER style: string.
@SET set_label_style: set the label style.
*/
#define set_label_style(ptr,lay)							set_dom_node_attr(ptr,ATTR_STYLE,-1,lay,-1)
/*
@PROPER style: string.
@GET get_label_style_ptr: get the label style.
*/
#define get_label_style_ptr(ptr)							get_dom_node_attr_ptr(ptr,ATTR_STYLE,-1)
/*
@PROPER width: numeric.
@GET get_label_width: get the label width.
*/
#define get_label_width(ptr)								get_dom_node_attr_float(ptr,ATTR_WIDTH)
/*
@PROPER width: numeric.
@SET set_label_width: set the label width.
*/
#define set_label_width(ptr,n)								set_dom_node_attr_float(ptr,ATTR_WIDTH,n)
/*
@PROPER height: numeric.
@GET get_label_height: get the label height.
*/
#define get_label_height(ptr)								get_dom_node_attr_float(ptr,ATTR_HEIGHT)
/*
@PROPER height: numeric.
@SET set_label_height: set the label height.
*/
#define set_label_height(ptr,n)								set_dom_node_attr_float(ptr,ATTR_HEIGHT,n)
/*
@PROPER itemWidth: numeric.
@GET get_label_item_width: get the label item width.
*/
#define get_label_item_width(ptr)							get_dom_node_attr_float(ptr,ATTR_ITEM_WIDTH)
/*
@PROPER itemWidth: numeric.
@SET set_label_item_width: set the label item width.
*/
#define set_label_item_width(ptr,n)							set_dom_node_attr_float(ptr,ATTR_ITEM_WIDTH,n)
/*
@PROPER itemHeight: numeric.
@GET get_label_item_height: get the label item height.
*/
#define get_label_item_height(ptr)							get_dom_node_attr_float(ptr,ATTR_ITEM_HEIGHT)
/*
@PROPER itemHeight: numeric.
@SET set_label_item_height: set the label item height.
*/
#define set_label_item_height(ptr,n)						set_dom_node_attr_float(ptr,ATTR_ITEM_HEIGHT,n)
/*
@PROPER name: string.
@GET get_label_item_name_ptr: get the label item name.
*/
#define get_label_item_name_ptr(ilk)						get_dom_node_attr_ptr(ilk,ATTR_NAME,-1)
/*
@PROPER name: string.
@SET set_label_item_name: set the label item name.
*/
#define set_label_item_name(ilk,token)						set_dom_node_attr(ilk,ATTR_NAME,-1,token,-1)
/*
@PROPER type: string.
@GET get_label_item_type_ptr: get the label item type.
*/
#define get_label_item_type_ptr(ilk)						get_dom_node_attr_ptr(ilk,ATTR_TEXT_TYPE,-1)
/*
@PROPER type: string.
@SET set_label_item_type: set the label item type.
*/
#define set_label_item_type(ilk,token)						set_dom_node_attr(ilk,ATTR_TEXT_TYPE,-1,token,-1)
/*
@PROPER icon: string.
@GET get_label_item_icon_ptr: get the label item icon.
*/
#define get_label_item_icon_ptr(ilk)						get_dom_node_attr_ptr(ilk,ATTR_ICON,-1)
/*
@PROPER icon: string.
@SET set_label_item_icon: set the label item icon.
*/
#define set_label_item_icon(ilk,token)						set_dom_node_attr(ilk,ATTR_ICON,-1,token,-1)
/*
@PROPER image: string.
@GET get_label_item_title_ptr: get the label item title.
*/
#define get_label_item_title_ptr(ilk)						get_dom_node_attr_ptr(ilk,ATTR_TITLE,-1)
/*
@PROPER image: string.
@SET set_label_item_title: set the label item title.
*/
#define set_label_item_title(ilk,token)						set_dom_node_attr(ilk,ATTR_TITLE,-1,token,-1)
/*
@PROPER text: string.
@GET get_label_item_text_ptr: get the label item text.
*/
#define get_label_item_text_ptr(ilk)						get_dom_node_text_ptr(ilk)
/*
@PROPER text: string.
@SET set_label_item_text: set the label item text.
*/
#define set_label_item_text(ilk,token,len)					set_dom_node_text(ilk,token,len)


#ifdef	__cplusplus
extern "C" {
#endif

/************************************************Functions***************************************************************************/

/*
@FUNCTION create_label_doc: create a label document.
@RETURN link_t_ptr: return the label document link component.
*/
EXP_API link_t_ptr create_label_doc(void);

/*
@FUNCTION destroy_label_doc: destroy a label document.
@INPUT link_t_ptr ptr: the label document link component.
@RETURN void: none.
*/
EXP_API void destroy_label_doc(link_t_ptr ptr);

/*
@FUNCTION get_label_itemset: get the label item set.
@INPUT link_t_ptr ptr: the label document link component.
@RETURN link_t_ptr: return the label item set .
*/
EXP_API link_t_ptr get_label_itemset(link_t_ptr ptr);

/*
@FUNCTION clear_label_doc: clear the label docuement.
@INPUT link_t_ptr ptr: the label document link component.
@RETURN void: none.
*/
EXP_API void clear_label_doc(link_t_ptr ptr);

/*
@FUNCTION is_label_doc: test is label docuement.
@INPUT link_t_ptr ptr: the label document link component.
@RETURN bool_t: return nonzero for being a lable document, otherwise return zero.
*/
EXP_API bool_t is_label_doc(link_t_ptr ptr);

/*
@FUNCTION is_label_item: test is label item.
@INPUT link_t_ptr ptr: the label document link component.
@INPUT link_t_ptr plk: the label item link component.
@RETURN bool_t: return nonzero for being a lable document, otherwise return zero.
*/
EXP_API bool_t is_label_item(link_t_ptr ptr, link_t_ptr plk);

/*
@FUNCTION label_doc_from_item: trackback item to label.
@INPUT link_t_ptr ilk: the label item link component.
@RETURN link_t_ptr: return the lable link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr label_doc_from_item(link_t_ptr ilk);

/*
@FUNCTION insert_label_item: add a new item to label at positoin.
@INPUT link_t_ptr ilk: the label item link component.
@INPUT link_t_ptr pos: the label item link component, or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return the new item link component.
*/
EXP_API link_t_ptr insert_label_item(link_t_ptr ptr,link_t_ptr pos);

/*
@FUNCTION get_label_next_item: get the next item in label.
@INPUT link_t_ptr ptr: the label document link component.
@INPUT link_t_ptr pos: the label item link component, or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return the next item link component.
*/
EXP_API link_t_ptr get_label_next_item(link_t_ptr ptr,link_t_ptr pos);

/*
@FUNCTION get_label_next_item: get the previous item in label.
@INPUT link_t_ptr ptr: the label document link component.
@INPUT link_t_ptr pos: the label item link component, or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return the previous item link component.
*/
EXP_API link_t_ptr get_label_prev_item(link_t_ptr ptr,link_t_ptr pos);

/*
@FUNCTION get_label_item_at: get item at posotion.
@INPUT link_t_ptr ptr: the label document link component.
@INPUT int index: the zero based position.
@RETURN link_t_ptr: return the item link component.
*/
EXP_API link_t_ptr get_label_item_at(link_t_ptr ptr, int index);

/*
@FUNCTION delete_label_item: delete the label item.
@INPUT link_t_ptr ilk: the label item link component.
@RETURN void: none.
*/
EXP_API void delete_label_item(link_t_ptr ilk);

/*
@FUNCTION get_label_item_count: counting the label items.
@INPUT link_t_ptr ptr: the label link component.
@RETURN int: return the number of label items.
*/
EXP_API int get_label_item_count(link_t_ptr ptr);

#ifdef	__cplusplus
}
#endif


#endif /*LABELDOC_H*/