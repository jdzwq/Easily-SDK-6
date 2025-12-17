/***********************************************************************
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

/**********************************************************************
@FUNCTION: create a tree.
@RETURN: return the tree link component.
***********************************************************************/
EXP_API link_t_ptr create_multi_tree(void);

/**********************************************************************
@FUNCTION: destroy a tree.
@INPUT: the tree link component.
@RETURN: none.
***********************************************************************/
EXP_API void destroy_multi_tree(link_t_ptr ptr);

/**********************************************************************
@FUNCTION: test is a tree.
@INPUT: the tree link component.
@RETURN: return nonzero for tree, otherwise return zero.
***********************************************************************/
EXP_API bool_t is_multi_tree(link_t_ptr ptr);

/**********************************************************************
@FUNCTION: test is a tree child node.
@INPUT: the tree link component.
@INPUT: the node link component.
@RETURN: return nonzero for tree node, otherwise return zero.
***********************************************************************/
EXP_API bool_t is_multi_child_node(link_t_ptr ilk, link_t_ptr plk);

/**********************************************************************
@FUNCTION: enum tree nodes.
@INPUT: the tree link component.
@INPUT: the callback function, the function return zero will breaking the enumeration.
@INPUT: the parameter translate into callback function.
@RETURN: return node link component breaked at, return NULL for none breaking.
***********************************************************************/
EXP_API link_t_ptr enum_multi_tree(link_t_ptr ptr, PF_ENUMLINK pf, void* param);

/**********************************************************************
@FUNCTION: enum tree nodes deep order.
@INPUT: the tree link component.
@INPUT: the callback function, the function return zero will breaking the enumeration.
@INPUT: the parameter translate into callback function.
@RETURN: return node link component breaked at, return NULL for none breaking.
***********************************************************************/
EXP_API link_t_ptr enum_multi_tree_deep(link_t_ptr ptr, PF_ENUMLINK pf, void* param);

/**********************************************************************
@FUNCTION: insert node into tree before the position.
@INPUT: the tree link component.
@INPUT: the positon node link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN: return node link component inserted.
***********************************************************************/
EXP_API link_t_ptr insert_multi_node_before(link_t_ptr ilk, link_t_ptr pos);

/**********************************************************************
@FUNCTION: insert node into tree after the position.
@INPUT: the tree link component.
@INPUT: the positon node link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN: return node link component inserted.
***********************************************************************/
EXP_API link_t_ptr insert_multi_node(link_t_ptr ilk, link_t_ptr pos);

/**********************************************************************
@FUNCTION: delete a node in tree.
@INPUT: the node link component.
@RETURN: none.
***********************************************************************/
EXP_API void delete_multi_node(link_t_ptr ilk);

/**********************************************************************
@FUNCTION: delete all child nodes.
@INPUT: the node link component.
@RETURN: none.
***********************************************************************/
EXP_API void delete_multi_child_nodes(link_t_ptr ilk);

/**********************************************************************
@FUNCTION: get child nodes count.
@INPUT: the node link component.
@RETURN: none.
***********************************************************************/
EXP_API int get_multi_child_node_count(link_t_ptr ilk);

/**********************************************************************
@FUNCTION: get the first child node.
@INPUT: the node link component.
@RETURN: return the node component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_multi_first_child_node(link_t_ptr ilk);

/**********************************************************************
@FUNCTION: get the last child node.
@INPUT: the node link component.
@RETURN: return the node component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_multi_last_child_node(link_t_ptr ilk);

/**********************************************************************
@FUNCTION: get the parent node.
@INPUT: the node link component.
@RETURN: return the node or tree link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_multi_parent_node(link_t_ptr ilk);

/**********************************************************************
@FUNCTION: get the next sibling node.
@INPUT: the node link component.
@RETURN: return the node link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_multi_next_sibling_node(link_t_ptr ilk);

/**********************************************************************
@FUNCTION: get the previous sibling node.
@INPUT: the node link component.
@RETURN: return the node link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_multi_prev_sibling_node(link_t_ptr ilk);

/**********************************************************************
@FUNCTION: get the node attributes hash table.
@INPUT: the node link component.
@RETURN: return the hash table link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_multi_node_attr_table(link_t_ptr ilk);

/**********************************************************************
@FUNCTION: get the node extract data.
@INPUT: the node link component.
@RETURN: return the extract data if exists, otherwise return zero.
***********************************************************************/
EXP_API vword_t get_multi_node_delta(link_t_ptr ilk);

/**********************************************************************
@FUNCTION: set the node extract data.
@INPUT: the node link component.
@INPUT: the extract data.
@RETURN: none.
***********************************************************************/
EXP_API void set_multi_node_delta(link_t_ptr ilk,vword_t delta);

/**********************************************************************
@FUNCTION: get the node mask.
@INPUT: the node link component.
@RETURN: return the node mask value.
***********************************************************************/
EXP_API dword_t get_multi_node_mask(link_t_ptr ilk);

/**********************************************************************
@FUNCTION: set the node mask value.
@INPUT: the node link component.
@INPUT: the mask value.
@RETURN: none.
***********************************************************************/
EXP_API void set_multi_node_mask(link_t_ptr ilk, dword_t ul);

/**********************************************************************
@FUNCTION: set the node mask bits.
@INPUT: the node link component.
@INPUT: the mask bits.
@INPUT: nonzero for setting, zero for clearing.
@RETURN: none.
***********************************************************************/
EXP_API void set_multi_node_mask_check(link_t_ptr ilk, dword_t ul, bool_t b);

/**********************************************************************
@FUNCTION: test the node mask bits is setted.
@INPUT: the node link component.
@INPUT: the mask bits.
@RETURN: if bits setted return nonzero, otherwise return zero.
***********************************************************************/
EXP_API bool_t get_multi_node_mask_check(link_t_ptr ilk, dword_t ul);

/**********************************************************************
@FUNCTION: counting the child nodes with mask bits setted.
@INPUT: the node link component.
@INPUT: the mask bits.
@RETURN: return the count of nodes with mask bits setted.
***********************************************************************/
EXP_API int get_multi_child_node_mask_check_count(link_t_ptr ilk, dword_t ul);

/**********************************************************************
@FUNCTION: set the child nodes mask bits to set or clear.
@INPUT: the node link component.
@INPUT: the mask bits.
@INPUT: nonzero for setting, zero for clearing.
@RETURN: return the count of nodes with mask bits setted or cleared.
***********************************************************************/
EXP_API int set_multi_child_node_mask_check(link_t_ptr ilk, dword_t ul, bool_t b);



#ifdef	__cplusplus
}
#endif


#endif /*_MULTITREE_H*/
