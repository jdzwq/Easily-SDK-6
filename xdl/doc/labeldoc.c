﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc label document

	@module	labeldoc.c | implement file

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

#include "labeldoc.h"

#include "../xdldoc.h"


void default_label_attr(link_t_ptr ptr) 
{
	set_label_style(ptr, _T("font-size:10.5;text-align:center;line-align:center;"));

	set_label_width(ptr, DEF_PAPER_WIDTH);
	set_label_height(ptr, DEF_PAPER_HEIGHT);
	set_label_item_height(ptr,50); 
	set_label_item_width(ptr,40); 
}

void default_label_item_attr(link_t_ptr ilk)
{
	set_label_item_type(ilk, ATTR_TEXT_TYPE_TEXT);
}

link_t_ptr create_label_doc()
{
	link_t_ptr ptr;

	ptr = create_dom_doc();
	set_dom_node_name(ptr,DOC_LABEL,-1);
	default_label_attr(ptr);

	return ptr;
}

void destroy_label_doc(link_t_ptr ptr)
{
	destroy_dom_doc(ptr);
}

link_t_ptr get_label_itemset(link_t_ptr ptr)
{
	return ptr;
}

void clear_label_doc(link_t_ptr ptr)
{
	ptr = get_label_itemset(ptr);

	delete_dom_child_nodes(ptr);
}

int get_label_item_count(link_t_ptr ptr)
{
	ptr = get_label_itemset(ptr);

	return get_dom_child_node_count(ptr);
}

link_t_ptr insert_label_item(link_t_ptr ptr,link_t_ptr pos)
{
	link_t_ptr blk;

	ptr = get_label_itemset(ptr);

	blk = insert_dom_node(ptr,pos);
	set_dom_node_name(blk,DOC_LABEL_ITEM,-1);

	default_label_item_attr(blk);

	return blk;
}

void delete_label_item(link_t_ptr ilk)
{
	delete_dom_node(ilk);
}

link_t_ptr get_label_next_item(link_t_ptr ptr,link_t_ptr pos)
{
	ptr = get_label_itemset(ptr);

	if (pos == LINK_FIRST)
		return get_dom_first_child_node(ptr);
	else if (pos == LINK_LAST)
		return NULL;
	else
		return get_dom_next_sibling_node(pos);
}

link_t_ptr get_label_prev_item(link_t_ptr ptr, link_t_ptr pos)
{
	ptr = get_label_itemset(ptr);

	if (pos == LINK_FIRST)
		return NULL;
	else if (pos == LINK_LAST)
		return get_dom_last_child_node(ptr);
	else
		return get_dom_prev_sibling_node(pos);
}

link_t_ptr get_label_item_at(link_t_ptr ptr,int index)
{
	ptr = get_label_itemset(ptr);

	return get_dom_child_node_at(ptr,index);
}

bool_t is_label_doc(link_t_ptr ptr)
{
	return (compare_text(get_dom_node_name_ptr(ptr),-1,DOC_LABEL,-1,0) == 0)? 1 : 0;
}

bool_t is_label_item(link_t_ptr ptr,link_t_ptr plk)
{
	return is_dom_child_node(ptr,plk);
}

link_t_ptr label_doc_from_item(link_t_ptr ilk)
{
	link_t_ptr ptr;

	ptr = ilk;
	do{
		if(is_label_doc(ptr))
			break;
		ptr = get_dom_parent_node(ptr);
	}while(ptr);

	return ptr;
}

