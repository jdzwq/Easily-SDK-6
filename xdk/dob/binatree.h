﻿/***********************************************************************
	Easily SDK 6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc binary tree document

	@module	binatree.h | interface file

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

#ifndef _BINATREE_H
#define _BINATREE_H

#include "../xdkdef.h"
/**********************************************************************************************************************/

typedef enum{
	_BINA_LEVEL_ZERO = 0,
	_BINA_LEVEL_RB = 1,
	_BINA_LEVEL_AVL = 2
}BINA_LEVEL;

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION create_bina_tree: create a binary tree.
@RETURN link_t_ptr: return the binary tree link component.
*/
EXP_API link_t_ptr create_bina_tree(int level);

/*
@FUNCTION destroy_bina_tree: destroy a binary tree.
@INPUT link_t_ptr ptr: the binary tree link component.
@RETURN void: none.
*/
EXP_API void destroy_bina_tree(link_t_ptr ptr);

/*
@FUNCTION insert_bina_node: insert a binary node.
@INPUT link_t_ptr ptr: the binary tree link component.
@INPUT variant_t key: the variant key.
@INPUT object_t val: the object value.
@RETURN link_t_ptr: return the node link component.
*/
EXP_API link_t_ptr insert_bina_node(link_t_ptr ptr, variant_t key, object_t val);

/*
@FUNCTION delete_bina_node: delete a binary node by key.
@INPUT link_t_ptr ptr: the binary tree link component.
@INPUT variant_t key: the variant key.
@RETURN bool_t: return nonzero if exists, otherwise return zero.
*/
EXP_API bool_t delete_bina_node(link_t_ptr ptr, variant_t key);

/*
@FUNCTION find_bina_node: find a binary node by key and return the value.
@INPUT link_t_ptr ptr: the binary tree link component.
@INPUT variant_t key: the variant key.
@OUTPUT object_t val: the object for returning value.
@RETURN link_t_ptr: return the node link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr find_bina_node(link_t_ptr ptr, variant_t key, object_t val);

/*
@FUNCTION attach_bina_leaf_object: attach value to node leaf, then the orginal leaf object will be freed.
@INPUT link_t_ptr nlk: the node link component.
@INPUT object_t val: the object value for attaching.
@RETURN void: none.
*/
EXP_API void attach_bina_leaf_object(link_t_ptr nlk, object_t val);

/*
@FUNCTION detach_bina_leaf_object: detach value from node left leaf, then the leaf value is empty.
@INPUT link_t_ptr nlk: the node link component.
@RETURN object_t: return the object value if exists, otherwise return NULL.
*/
EXP_API object_t detach_bina_leaf_object(link_t_ptr nlk);

/*
@FUNCTION get_bina_left_child_node: get left child node.
@INPUT link_t_ptr nlk: the node link component.
@RETURN link_t_ptr: return the left child node link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_bina_left_child_node(link_t_ptr nlk);

/*
@FUNCTION get_bina_right_child_node: get right child node.
@INPUT link_t_ptr nlk: the node link component.
@RETURN link_t_ptr: return the right child node link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_bina_right_child_node(link_t_ptr nlk);

/*
@FUNCTION get_bina_parent_node: get parent node.
@INPUT link_t_ptr nlk: the node link component.
@RETURN link_t_ptr: return the parent node link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_bina_parent_node(link_t_ptr nlk);

/*
@FUNCTION is_bina_leaf: test is a leaf node.
@INPUT link_t_ptr nlk: the node link component.
@RETURN bool_t: return nonzero for a leaf node, otherwise return zero.
*/
EXP_API bool_t is_bina_leaf(link_t_ptr nlk);

/*
@FUNCTION traver_bina_tree_preorder: enum the binary tree nodes by preorder.
@INPUT link_t_ptr ptr: the binary tree link component.
@INPUT CALLBACK_ENUMLINK pf: the callback function, if the call return zero, the travering will be breaked.
@INPUT void* param: parameter translate into callback function.
@RETURN link_t_ptr: return node link component breaked at.
*/
EXP_API link_t_ptr traver_bina_tree_preorder(link_t_ptr ptr, CALLBACK_ENUMLINK pf, void* param);

/*
@FUNCTION traver_bina_tree_postorder: enum the binary tree nodes by postorder.
@INPUT link_t_ptr ptr: the binary tree link component.
@INPUT CALLBACK_ENUMLINK pf: the callback function, if the call return zero, the travering will be breaked.
@INPUT void* param: parameter translate into callback function.
@RETURN link_t_ptr: return node link component breaked at.
*/
EXP_API link_t_ptr traver_bina_tree_postorder(link_t_ptr ptr, CALLBACK_ENUMLINK pf, void* param);

/*
@FUNCTION traver_bina_tree_inorder: enum the binary tree nodes by inorder.
@INPUT link_t_ptr ptr: the binary tree link component.
@INPUT CALLBACK_ENUMLINK pf: the callback function, if the call return zero, the travering will be breaked.
@INPUT void* param: parameter translate into callback function.
@RETURN link_t_ptr: return node link component breaked at.
*/
EXP_API link_t_ptr traver_bina_tree_inorder(link_t_ptr ptr, CALLBACK_ENUMLINK pf, void* param);

/*
@FUNCTION traver_bina_tree_levelorder: enum the binary tree nodes by level order.
@INPUT link_t_ptr ptr: the binary tree link component.
@INPUT CALLBACK_ENUMLINK pf: the callback function, if the call return zero, the travering will be breaked.
@INPUT void* param: parameter translate into callback function.
@RETURN link_t_ptr: return node link component breaked at.
*/
EXP_API link_t_ptr traver_bina_tree_levelorder(link_t_ptr ptr, CALLBACK_ENUMLINK pf, void* param);

#if defined(XDK_SUPPORT_TEST)
	EXP_API void test_bina_tree();
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_BINATREE_H*/
