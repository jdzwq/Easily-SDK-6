﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc status document

	@module	statusdoc.c | implement file

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

#include "statusdoc.h"

#include "../xdldoc.h"


void default_status_attr(link_t_ptr ptr)
{
	set_status_style(ptr, _T("font-size:9;text-align:near;line-align:center;"));
	set_status_icon_span(ptr, DEF_ICON_SPAN);
}

link_t_ptr create_status_doc()
{
	link_t_ptr ptr;

	ptr = create_dom_doc();
	set_dom_node_name(ptr,DOC_STATUS,-1);
	default_status_attr(ptr);

	return ptr;
}

void destroy_status_doc(link_t_ptr ptr)
{
	destroy_dom_doc(ptr);
}

link_t_ptr get_status_itemset(link_t_ptr ptr)
{
	return ptr;
}

bool_t is_status_doc(link_t_ptr ptr)
{
	return (compare_text(get_dom_node_name_ptr(ptr),-1,DOC_STATUS,-1,0) == 0)? 1 : 0;
}

bool_t is_status_item(link_t_ptr ptr,link_t_ptr ilk)
{
	return is_dom_child_node(ptr,ilk);
}

void clear_status_doc(link_t_ptr ptr)
{
	ptr = get_status_itemset(ptr);

	delete_dom_child_nodes(ptr);
}

link_t_ptr insert_status_item(link_t_ptr ptr,link_t_ptr pos)
{
	link_t_ptr ilk;

	ptr = get_status_itemset(ptr);

	ilk = insert_dom_node(ptr,pos);
	set_dom_node_name(ilk,DOC_STATUS_ITEM,-1);

	set_status_item_width(ilk, 25);

	return ilk;
}

void delete_status_item(link_t_ptr ilk)
{
	delete_dom_node(ilk);
}

int get_status_item_count(link_t_ptr ptr)
{
	ptr = get_status_itemset(ptr);

	return get_dom_child_node_count(ptr);
}

link_t_ptr get_status_next_item(link_t_ptr ptr,link_t_ptr pos)
{
	ptr = get_status_itemset(ptr);

	if(pos == LINK_FIRST)
		return get_dom_first_child_node(ptr);
	else if(pos == LINK_LAST)
		return NULL;
	else
		return get_next_link(pos);
}

link_t_ptr get_status_prev_item(link_t_ptr ptr,link_t_ptr pos)
{
	ptr = get_status_itemset(ptr);

	if(pos == LINK_FIRST)
		return NULL;
	else if(pos == LINK_LAST)
		return get_dom_last_child_node(ptr);
	else
		return get_prev_link(pos);
}

link_t_ptr get_status_item(link_t_ptr ptr, const tchar_t* cname)
{
	link_t_ptr tlk;

	tlk = get_status_next_item(ptr, LINK_FIRST);
	while (tlk)
	{
		if (xscmp(get_status_item_name_ptr(tlk), cname) == 0)
			return tlk;
		tlk = get_status_next_item(ptr, tlk);
	}
	return NULL;
}
