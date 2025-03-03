﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc tree document

	@module	treedoc.h | interface file

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

#ifndef _TREEDOC_H
#define _TREEDOC_H

#include "../xdldef.h"


/************************************************Properties***************************************************************************/

/*
@PROPER style: string.
@GET get_tree_style_ptr: get the tree style.
*/
#define get_tree_style_ptr(ptr)							get_dom_node_attr_ptr(ptr,ATTR_STYLE,-1)
/*
@PROPER style: string.
@SET set_tree_style: set the tree style.
*/
#define set_tree_style(ptr,token)						set_dom_node_attr(ptr,ATTR_STYLE,-1,token,-1)
/*
@PROPER name: string.
@GET get_tree_name_ptr: get the tree name.
*/
#define get_tree_name_ptr(ptr)							get_dom_node_attr_ptr(ptr,ATTR_NAME,-1)
/*
@PROPER name: string.
@SET set_tree_name: set the tree name.
*/
#define set_tree_name(ptr,token)						set_dom_node_attr(ptr,ATTR_NAME,-1,token,-1)
/*
@PROPER title: string.
@SET set_tree_title: set the tree title.
*/
#define set_tree_title(ptr,token)						set_dom_node_attr(ptr,ATTR_TITLE,-1,token,-1)
/*
@PROPER title: string.
@GET get_tree_title_ptr: get the tree title.
*/
#define get_tree_title_ptr(ptr)							get_dom_node_attr_ptr(ptr,ATTR_TITLE,-1)
/*
@PROPER width: numeric.
@SET set_tree_width: set the tree width.
*/
#define set_tree_width(ptr,n)							set_dom_node_attr_float(ptr,ATTR_WIDTH,n)
/*
@PROPER width: numeric.
@GET get_tree_width: get the tree width.
*/
#define get_tree_width(ptr)								get_dom_node_attr_float(ptr,ATTR_WIDTH)
/*
@PROPER height: numeric.
@GET get_tree_height: get the tree height.
*/
#define get_tree_height(ptr)							get_dom_node_attr_float(ptr,ATTR_HEIGHT)
/*
@PROPER height: numeric.
@SET set_tree_height: set the tree height.
*/
#define set_tree_height(ptr,n)							set_dom_node_attr_float(ptr,ATTR_HEIGHT,n)
/*
@PROPER titleHeight: numeric.
@GET get_tree_title_height: get the tree title height.
*/
#define get_tree_title_height(ptr)						get_dom_node_attr_float(ptr,ATTR_TITLE_HEIGHT)
/*
@PROPER titleHeight: numeric.
@SET set_tree_title_height: set the tree title height.
*/
#define set_tree_title_height(ptr,n)					set_dom_node_attr_float(ptr,ATTR_TITLE_HEIGHT,n)
/*
@PROPER titleImage: string.
@GET get_tree_title_icon_ptr: get the tree title icon.
*/
#define get_tree_title_icon_ptr(ptr)					get_dom_node_attr_ptr(ptr,ATTR_ICON,-1)
/*
@PROPER titleImage: string.
@SET set_tree_title_icon: set the tree title icon.
*/
#define set_tree_title_icon(ptr,token)					set_dom_node_attr(ptr,ATTR_ICON,-1,token,-1)
/*
@PROPER iconSpan: numeric.
@SET set_tree_icon_span: set the tree icon span.
*/
#define set_tree_icon_span(ptr,n)						set_dom_node_attr_float(ptr,ATTR_ICON_SPAN,n)
/*
@PROPER iconSpan: numeric.
@GET get_tree_icon_span: get the tree icon span.
*/
#define get_tree_icon_span(ptr)							get_dom_node_attr_float(ptr,ATTR_ICON_SPAN)
/*
@PROPER itemHeight: numeric.
@GET get_tree_item_height: get the tree item height.
*/
#define get_tree_item_height(ptr)						get_dom_node_attr_float(ptr,ATTR_ITEM_HEIGHT)
/*
@PROPER itemHeight: numeric.
@SET set_tree_item_height: set the tree item height.
*/
#define set_tree_item_height(ptr,n)						set_dom_node_attr_float(ptr,ATTR_ITEM_HEIGHT,n)
/*
@PROPER name: string.
@SET set_tree_item_name: set the tree item name.
*/
#define set_tree_item_name(ilk,token)					set_dom_node_attr(ilk,ATTR_NAME,-1,token,-1)
/*
@PROPER name: string.
@GET get_tree_item_name_ptr: get the tree item name.
*/
#define get_tree_item_name_ptr(ilk)						get_dom_node_attr_ptr(ilk,ATTR_NAME,-1)
/*
@PROPER title: string.
@SET set_tree_item_title: set the tree item title.
*/
#define set_tree_item_title(ilk,token)					set_dom_node_attr(ilk,ATTR_TITLE,-1,token,-1)
/*
@PROPER title: string.
@GET get_tree_item_id_ptr: get the tree item title.
*/
#define get_tree_item_title_ptr(ilk)					get_dom_node_attr_ptr(ilk,ATTR_TITLE,-1)
/*
@PROPER id: string.
@SET set_tree_item_id: set the tree item id.
*/
#define set_tree_item_id(ilk,token)						set_dom_node_attr(ilk,ATTR_ID,-1,token,-1)
/*
@PROPER id: string.
@GET get_tree_item_id_ptr: get the tree item title.
*/
#define get_tree_item_id_ptr(ilk)						get_dom_node_attr_ptr(ilk,ATTR_ID,-1)
/*
@PROPER showCheck: boolean.
@GET get_tree_item_showcheck: get the tree item show check box.
*/
#define get_tree_item_showcheck(ilk)					get_dom_node_attr_boolean(ilk,ATTR_SHOWCHECK)
/*
@PROPER showCheck: boolean.
@SET set_tree_item_showcheck: set the tree item show check box.
*/
#define set_tree_item_showcheck(ilk,b)					set_dom_node_attr_boolean(ilk,ATTR_SHOWCHECK,b)
/*
@PROPER icon: string.
@GET get_tree_item_icon_ptr: get the tree item icon.
*/
#define get_tree_item_icon_ptr(ilk)						get_dom_node_attr_ptr(ilk,ATTR_ICON,-1)
/*
@PROPER icon: string.
@SET set_tree_item_icon: set the tree item icon.
*/
#define set_tree_item_icon(ilk,token)					set_dom_node_attr(ilk,ATTR_ICON,-1,token,-1)
/*
@PROPER locked: boolean.
@SET set_tree_item_locked: set the tree item locked.
*/
#define set_tree_item_locked(ilk,c)						set_dom_node_mask_check(ilk,MSK_LOCKED,c) 
/*
@PROPER images: document.
@GET get_tree_item_locked: get the tree item locked.
*/
#define get_tree_item_locked(ilk)						get_dom_node_mask_check(ilk,MSK_LOCKED)
/*
@PROPER collapsed: boolean.
@SET set_tree_item_collapsed: set the tree item collapsed.
*/
#define set_tree_item_collapsed(ilk,b)				set_dom_node_mask_check(ilk,MSK_COLLAPSED,b)
/*
@PROPER collapsed: document.
@GET get_tree_item_collapsed: get the tree item collapsed.
*/
#define get_tree_item_collapsed(ilk)						get_dom_node_mask_check(ilk,MSK_COLLAPSED)
/*
@PROPER checked: boolean.
@SET set_tree_item_checked: set the tree item checked.
*/
#define set_tree_item_checked(ilk,check)				set_dom_node_mask_check(ilk,MSK_CHECKED,check) 
/*
@PROPER checked: boolean.
@GET get_tree_item_checked: get the tree item checked.
*/
#define get_tree_item_checked(ilk)						get_dom_node_mask_check(ilk,MSK_CHECKED)
/*
@PROPER delta: vword_t.
@SET set_tree_item_delta: set the tree item extract data.
*/
#define set_tree_item_delta(ilk,ul)						set_dom_node_delta(ilk,(vword_t)ul)
/*
@PROPER delta: vword_t.
@GET get_tree_item_delta: get the tree item extract data.
*/
#define get_tree_item_delta(ilk)						get_dom_node_delta(ilk)


#ifdef	__cplusplus
extern "C" {
#endif

/************************************************Functions***************************************************************************/

/*
@FUNCTION create_tree_doc: create a tree document.
@RETURN link_t_ptr: return the tree document link component.
*/
EXP_API link_t_ptr create_tree_doc(void);

/*
@FUNCTION destroy_tree_doc: destroy a tree document.
@INPUT link_t_ptr ptr: the tree link component.
@RETURN void: none.
*/
EXP_API void destroy_tree_doc(link_t_ptr ptr);

/*
@FUNCTION is_tree_doc: test is tree document.
@INPUT link_t_ptr ptr: the tree link component.
@RETURN bool_t: return nonzero for being a tree document, otherwise return zero.
*/
EXP_API bool_t is_tree_doc(link_t_ptr ptr);

/*
@FUNCTION clear_tree_doc: clear the tree document.
@INPUT link_t_ptr ptr: the tree link component.
@RETURN void: none.
*/
EXP_API void clear_tree_doc(link_t_ptr ptr);

/*
@FUNCTION is_tree_item: test is tree item node.
@INPUT link_t_ptr ptr: the tree link component.
@INPUT link_t_ptr ilk: the item link component.
@RETURN bool_t: return nonzero for being a tree item, otherwise return zero.
*/
EXP_API bool_t is_tree_item(link_t_ptr ptr, link_t_ptr ilk);

/*
@FUNCTION insert_tree_item: add a new item to tree document.
@INPUT link_t_ptr ilk: the parent item link component.
@INPUT link_t_ptr pos: the item link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return the new item link component.
*/
EXP_API link_t_ptr insert_tree_item(link_t_ptr ilk, link_t_ptr pos);

/*
@FUNCTION delete_tree_item: delete the tree item.
@INPUT link_t_ptr ilk: the item link component.
@RETURN void: none.
*/
EXP_API void delete_tree_item(link_t_ptr ilk);

/*
@FUNCTION delete_tree_child_items: delete all of child items.
@INPUT link_t_ptr ilk: the parent item link component.
@RETURN void: none.
*/
EXP_API void delete_tree_child_items(link_t_ptr ilk);

/*
@FUNCTION get_tree_item_level: get the item level.
@INPUT link_t_ptr ilk: the item link component.
@RETURN int: return the zero based level index.
*/
EXP_API int get_tree_item_level(link_t_ptr ilk);

/*
@FUNCTION get_tree_child_item_count: counting the tree child items.
@INPUT link_t_ptr ptr: the parent item link component.
@RETURN int: return the number of items.
*/
EXP_API int get_tree_child_item_count(link_t_ptr ilk);

/*
@FUNCTION get_tree_first_child_item: get the first child item.
@INPUT link_t_ptr ilk: the parent item link component.
@RETURN link_t_ptr: return the item link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_tree_first_child_item(link_t_ptr ilk);

/*
@FUNCTION get_tree_last_child_item: get the last child item.
@INPUT link_t_ptr ilk: the parent item link component.
@RETURN link_t_ptr: return the item link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_tree_last_child_item(link_t_ptr ilk);

/*
@FUNCTION get_tree_parent_item: get the parent item.
@INPUT link_t_ptr ilk: the item link component.
@RETURN link_t_ptr: return the parent item link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_tree_parent_item(link_t_ptr ilk);

/*
@FUNCTION get_tree_next_sibling_item: get the next sibling item.
@INPUT link_t_ptr ilk: the item link component.
@RETURN link_t_ptr: return the next sibling item link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_tree_next_sibling_item(link_t_ptr ilk);

/*
@FUNCTION get_tree_prev_sibling_item: get the previous sibling item.
@INPUT link_t_ptr ilk: the item link component.
@RETURN link_t_ptr: return the previous sibling item link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_tree_prev_sibling_item(link_t_ptr ilk);

/*
@FUNCTION get_tree_next_visible_item: get the next visible sibling item.
@INPUT link_t_ptr ilk: the item link component.
@RETURN link_t_ptr: return the next sibling item link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_tree_next_visible_item(link_t_ptr ptr,link_t_ptr pos);

/*
@FUNCTION get_tree_prev_visible_item: get the previous visible sibling item.
@INPUT link_t_ptr ilk: the item link component.
@RETURN link_t_ptr: return the previous sibling item link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_tree_prev_visible_item(link_t_ptr ptr,link_t_ptr pos);

/*
@FUNCTION find_tree_item_by_name: find tree item by name.
@INPUT link_t_ptr ptr: the tree link component.
@INPUT const tchar_t* sz_name: the name string token.
@RETURN link_t_ptr: return the item link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr find_tree_item_by_name(link_t_ptr ptr, const tchar_t* sz_name);

/*
@FUNCTION find_tree_item_by_title: find tree item by title.
@INPUT link_t_ptr ptr: the tree link component.
@INPUT const tchar_t* sz_title: the title string token.
@RETURN link_t_ptr: return the item link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr find_tree_item_by_title(link_t_ptr ptr, const tchar_t* sz_title);

#ifdef	__cplusplus
}
#endif


#endif /*_TREEDOC_H*/
