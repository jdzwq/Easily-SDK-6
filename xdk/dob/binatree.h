/***********************************************************************
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


/***********************************************************************
@FUNCTION: create b-tree.
@INPUT: the balence level of b-tree.
@RETURN: the link component of b-tree or NULL if failed.
***********************************************************************/
EXP_API link_t_ptr create_bina_tree(int level);

/***********************************************************************
@FUNCTION: destroy b-tree.
@INPUT: the link component of b-tree.
@RETURN: none.
***********************************************************************/
EXP_API void destroy_bina_tree(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: insert a pair of key-value into b-tree.
@INPUT: the link component of b-tree.
@INPUT: the key identify.
@INPUT: the value object.
@RETURN: none.
@NOTE: if the key identify exists in b-tree then the value object to be replaced,
	otherwise new key-value to be added.
***********************************************************************/
EXP_API link_t_ptr insert_bina_node(link_t_ptr ptr, variant_t key, object_t val);

/***********************************************************************
@FUNCTION: delete a pair of key-value from b-tree.
@INPUT: the link component of b-tree.
@INPUT: the key identify.
@RETURN: if key-value pair exists in b-tree then delete it and return none-zero,
	otherwise return zero.
***********************************************************************/
EXP_API bool_t delete_bina_node(link_t_ptr ptr, variant_t key);

/***********************************************************************
@FUNCTION: find the key-value pair in b-tree.
@INPUT: the link component of b-tree.
@INPUT: the key identify.
@INPUT: the value object.
@RETURN: the link component of key-value pair node, or NULL if not find.
***********************************************************************/
EXP_API link_t_ptr find_bina_node(link_t_ptr ptr, variant_t key, object_t val);

/***********************************************************************
@FUNCTION: attach a value to key-value pair node.
@INPUT: the link component of key-value pair node.
@INPUT: the value object to attach.
@RETURN: none.
@NOTE: the origin value object need to detached first.
***********************************************************************/
EXP_API void attach_bina_leaf_object(link_t_ptr nlk, object_t val);

/***********************************************************************
@FUNCTION: detach a value from key-value pair node.
@INPUT: the link component of key-value pair node.
@RETURN: the value object.
@NOTE: after detached, the value in the key-value pair node is empty.
***********************************************************************/
EXP_API object_t detach_bina_leaf_object(link_t_ptr nlk);

/***********************************************************************
@FUNCTION: get left child node.
@INPUT: the link component of key-value pair node.
@RETURN: the link component of child node.
***********************************************************************/
EXP_API link_t_ptr get_bina_left_child_node(link_t_ptr nlk);

/***********************************************************************
@FUNCTION: get right child node.
@INPUT: the link component of key-value pair node.
@RETURN: the link component of child node.
***********************************************************************/
EXP_API link_t_ptr get_bina_right_child_node(link_t_ptr nlk);

/***********************************************************************
@FUNCTION: get parent node.
@INPUT: the link component of key-value pair node.
@RETURN: the link component of child node.
***********************************************************************/
EXP_API link_t_ptr get_bina_parent_node(link_t_ptr nlk);

/***********************************************************************
@FUNCTION: test is or not a leaf node.
@INPUT: the link component of key-value pair node.
@RETURN: non-zero if leaf node, zero for not.
***********************************************************************/
EXP_API bool_t is_bina_leaf(link_t_ptr nlk);

/***********************************************************************
@FUNCTION: num the binary tree nodes by preorder.
@INPUT: the link component of b-tree.
@INPUT: the callback function for getting one key-value per called.
@INPUT: the user-parameter trans back to callback function.
@RETURN: none.
@NOTE: if the callback function return none-zero, the enumerating breaked.
***********************************************************************/
EXP_API link_t_ptr traver_bina_tree_preorder(link_t_ptr ptr, PF_ENUMLINK pf, void* param);

/***********************************************************************
@FUNCTION: num the binary tree nodes by postorder.
@INPUT: the link component of b-tree.
@INPUT: the callback function for getting one key-value per called.
@INPUT: the user-parameter trans back to callback function.
@RETURN: none.
@NOTE: if the callback function return none-zero, the enumerating breaked.
***********************************************************************/
EXP_API link_t_ptr traver_bina_tree_postorder(link_t_ptr ptr, PF_ENUMLINK pf, void* param);

/***********************************************************************
@FUNCTION: num the binary tree nodes by inorder.
@INPUT: the link component of b-tree.
@INPUT: the callback function for getting one key-value per called.
@INPUT: the user-parameter trans back to callback function.
@RETURN: none.
@NOTE: if the callback function return none-zero, the enumerating breaked.
***********************************************************************/
EXP_API link_t_ptr traver_bina_tree_inorder(link_t_ptr ptr, PF_ENUMLINK pf, void* param);

/***********************************************************************
@FUNCTION: num the binary tree nodes by level-order.
@INPUT: the link component of b-tree.
@INPUT: the callback function for getting one key-value per called.
@INPUT: the user-parameter trans back to callback function.
@RETURN: none.
@NOTE: if the callback function return none-zero, the enumerating breaked.
***********************************************************************/
EXP_API link_t_ptr traver_bina_tree_levelorder(link_t_ptr ptr, PF_ENUMLINK pf, void* param);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void bina_tree_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_BINATREE_H*/
