/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc stacktable document

	@module	stacktable.h | interface file

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

#ifndef _STACKTABLE_H
#define _STACKTABLE_H

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************************************
@FUNCTION: create a stack table.
@RETURN: return the stack table link component.
***********************************************************************/
EXP_API link_t_ptr create_stack_table(void);

/**********************************************************************
@FUNCTION: destroy a stack table.
@INPUT: the stack table link component.
@RETURN: none.
***********************************************************************/
EXP_API void destroy_stack_table(link_t_ptr st);

/**********************************************************************
@FUNCTION: clear a stack table contents.
@INPUT: the stack table link component.
@RETURN: none.
***********************************************************************/
EXP_API void clear_stack_table(link_t_ptr st);

/**********************************************************************
@FUNCTION: push a node into stack table.
@INPUT: the stack table link component.
@INPUT: the data pointer.
@RETURN: none.
***********************************************************************/
EXP_API void push_stack_node(link_t_ptr st,void* data);

/**********************************************************************
@FUNCTION: pop top node from stack table.
@INPUT: the stack table link component.
@RETURN: if stack has top node, return the data pointer, 
	otherwise return NULL, and the node removed.
***********************************************************************/
EXP_API void* pop_stack_node(link_t_ptr st);

/**********************************************************************
@FUNCTION: pick top node from stack table.
@INPUT: the stack table link component.
@RETURN: if stack has top node, return the data pointer, otherwise return NULL.
***********************************************************************/
EXP_API void* pick_stack_node(link_t_ptr st);

/**********************************************************************
@FUNCTION: get nodes count from stack table.
@INPUT: the stack table link component.
@RETURN: the nodes in stack table.
***********************************************************************/
EXP_API int get_stack_node_count(link_t_ptr st);

/**********************************************************************
@FUNCTION: peek node at some position from stack table.
@INPUT: the stack table link component.
@INPUT: the zero-based position.
@RETURN: if the position has node, return the data pointer, otherwise return NULL.
***********************************************************************/
EXP_API void* peek_stack_node(link_t_ptr st, int index);

#ifdef	__cplusplus
}
#endif

#endif /*_STACKTABLE_H*/