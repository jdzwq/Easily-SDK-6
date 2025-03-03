﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc multi tree document

	@module	multitree.h | interface file

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

#ifndef _MULTITREE_H
#define _MULTITREE_H

#include "../xdkdef.h"

/****************************************************************************************************************************/
#define set_multi_node_attr(ptr,key,keylen,val,vallen)	write_hash_attr(get_multi_node_attr_table(ptr),key,keylen,val,vallen)

#define get_multi_node_attr(ptr,key,keylen,buf,max)		read_hash_attr(get_multi_node_attr_table(ptr),key,keylen,buf,max)

#define get_multi_node_attr_ptr(ptr,key,keylen)			get_hash_attr_ptr(get_multi_node_attr_table(ptr),key,keylen)

#define get_multi_node_attr_len(ptr,key,keylen)			get_hash_attr_len(get_multi_node_attr_table(ptr),key,keylen)
/*************************************************************************************************************************/

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION create_multi_tree: create a tree.
@RETURN link_t_ptr: return the tree link component.
*/
EXP_API link_t_ptr create_multi_tree(void);

/*
@FUNCTION destroy_multi_tree: destroy a tree.
@INPUT link_t_ptr ptr: the tree link component.
@RETURN void: none.
*/
EXP_API void destroy_multi_tree(link_t_ptr ptr);

/*
@FUNCTION is_multi_tree: test is a tree.
@INPUT link_t_ptr ptr: the tree link component.
@RETURN bool_t: return nonzero for tree, otherwise return zero.
*/
EXP_API bool_t is_multi_tree(link_t_ptr ptr);

/*
@FUNCTION is_multi_child_node: test is a tree child node.
@INPUT link_t_ptr ptr: the tree link component.
@INPUT link_t_ptr plk: the node link component.
@RETURN bool_t: return nonzero for tree node, otherwise return zero.
*/
EXP_API bool_t is_multi_child_node(link_t_ptr ilk, link_t_ptr plk);

/*
@FUNCTION enum_multi_tree: enum tree nodes.
@INPUT link_t_ptr ptr: the tree link component.
@INPUT CALLBACK_ENUMLINK pf: the callback function, the function return zero will breaking the enumeration.
@INPUT void* param: the parameter translate into callback function.
@RETURN link_t_ptr: return node link component breaked at, return NULL for none breaking.
*/
EXP_API link_t_ptr enum_multi_tree(link_t_ptr ptr, CALLBACK_ENUMLINK pf, void* param);

/*
@FUNCTION enum_multi_tree_deep: enum tree nodes deep order.
@INPUT link_t_ptr ptr: the tree link component.
@INPUT CALLBACK_ENUMLINK pf: the callback function, the function return zero will breaking the enumeration.
@INPUT void* param: the parameter translate into callback function.
@RETURN link_t_ptr: return node link component breaked at, return NULL for none breaking.
*/
EXP_API link_t_ptr enum_multi_tree_deep(link_t_ptr ptr, CALLBACK_ENUMLINK pf, void* param);

/*
@FUNCTION insert_multi_node_before: insert node into tree before the position.
@INPUT link_t_ptr ptr: the tree link component.
@INPUT link_t_ptr pos: the positon node link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return node link component inserted.
*/
EXP_API link_t_ptr insert_multi_node_before(link_t_ptr ilk, link_t_ptr pos);

/*
@FUNCTION insert_multi_node: insert node into tree after the position.
@INPUT link_t_ptr ptr: the tree link component.
@INPUT link_t_ptr pos: the positon node link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return node link component inserted.
*/
EXP_API link_t_ptr insert_multi_node(link_t_ptr ilk, link_t_ptr pos);

/*
@FUNCTION delete_multi_node: delete a node in tree.
@INPUT link_t_ptr ilk: the node link component.
@RETURN void: none.
*/
EXP_API void delete_multi_node(link_t_ptr ilk);

/*
@FUNCTION delete_multi_child_nodes: delete all child nodes.
@INPUT link_t_ptr ilk: the node link component.
@RETURN void: none.
*/
EXP_API void delete_multi_child_nodes(link_t_ptr ilk);

/*
@FUNCTION get_multi_child_node_count: get child nodes count.
@INPUT link_t_ptr ilk: the node link component.
@RETURN void: none.
*/
EXP_API int get_multi_child_node_count(link_t_ptr ilk);

/*
@FUNCTION get_multi_first_child_node: get the first child node.
@INPUT link_t_ptr ilk: the node link component.
@RETURN link_t_ptr: return the node component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_multi_first_child_node(link_t_ptr ilk);

/*
@FUNCTION get_multi_last_child_node: get the last child node.
@INPUT link_t_ptr ilk: the node link component.
@RETURN link_t_ptr: return the node component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_multi_last_child_node(link_t_ptr ilk);

/*
@FUNCTION get_multi_parent_node: get the parent node.
@INPUT link_t_ptr ilk: the node link component.
@RETURN link_t_ptr: return the node or tree link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_multi_parent_node(link_t_ptr ilk);

/*
@FUNCTION get_multi_next_sibling_node: get the next sibling node.
@INPUT link_t_ptr ilk: the node link component.
@RETURN link_t_ptr: return the node link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_multi_next_sibling_node(link_t_ptr ilk);

/*
@FUNCTION get_multi_prev_sibling_node: get the previous sibling node.
@INPUT link_t_ptr ilk: the node link component.
@RETURN link_t_ptr: return the node link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_multi_prev_sibling_node(link_t_ptr ilk);

/*
@FUNCTION get_multi_node_attr_table: get the node attributes hash table.
@INPUT link_t_ptr ilk: the node link component.
@RETURN link_t_ptr: return the hash table link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_multi_node_attr_table(link_t_ptr ilk);

/*
@FUNCTION get_multi_node_delta: get the node extract data.
@INPUT link_t_ptr ilk: the node link component.
@RETURN vword_t: return the extract data if exists, otherwise return zero.
*/
EXP_API vword_t get_multi_node_delta(link_t_ptr ilk);

/*
@FUNCTION set_multi_node_delta: set the node extract data.
@INPUT link_t_ptr ilk: the node link component.
@INPUT vword_t delta: the extract data.
@RETURN void: none.
*/
EXP_API void set_multi_node_delta(link_t_ptr ilk,vword_t delta);

/*
@FUNCTION get_multi_node_mask: get the node mask.
@INPUT link_t_ptr ilk: the node link component.
@RETURN dword_t: return the node mask value.
*/
EXP_API dword_t get_multi_node_mask(link_t_ptr ilk);

/*
@FUNCTION set_multi_node_mask: set the node mask value.
@INPUT link_t_ptr ilk: the node link component.
@INPUT dword_t ul: the mask value.
@RETURN void: none.
*/
EXP_API void set_multi_node_mask(link_t_ptr ilk, dword_t ul);

/*
@FUNCTION set_multi_node_mask_check: set the node mask bits.
@INPUT link_t_ptr ilk: the node link component.
@INPUT dword_t ul: the mask bits.
@INPUT bool_t b: nonzero for setting, zero for clearing.
@RETURN void: none.
*/
EXP_API void set_multi_node_mask_check(link_t_ptr ilk, dword_t ul, bool_t b);

/*
@FUNCTION get_multi_node_mask_check: test the node mask bits is setted.
@INPUT link_t_ptr ilk: the node link component.
@INPUT dword_t ul: the mask bits.
@RETURN bool_t: if bits setted return nonzero, otherwise return zero.
*/
EXP_API bool_t get_multi_node_mask_check(link_t_ptr ilk, dword_t ul);

/*
@FUNCTION get_multi_child_node_mask_check_count: counting the child nodes with mask bits setted.
@INPUT link_t_ptr ilk: the node link component.
@INPUT dword_t ul: the mask bits.
@RETURN int: return the count of nodes with mask bits setted.
*/
EXP_API int get_multi_child_node_mask_check_count(link_t_ptr ilk, dword_t ul);

/*
@FUNCTION set_multi_child_node_mask_check: set the child nodes mask bits to set or clear.
@INPUT link_t_ptr ilk: the node link component.
@INPUT dword_t ul: the mask bits.
@INPUT bool_t b: nonzero for setting, zero for clearing.
@RETURN int: return the count of nodes with mask bits setted or cleared.
*/
EXP_API int set_multi_child_node_mask_check(link_t_ptr ilk, dword_t ul, bool_t b);



#ifdef	__cplusplus
}
#endif


#endif /*_MULTITREE_H*/
