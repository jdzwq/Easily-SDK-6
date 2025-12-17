/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc trie tree document

	@module	trietree.h | interface file

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

#ifndef _TRIETREE_H
#define _TRIETREE_H

#include "../xdkdef.h"

/**********************************************************************************************************************/

typedef bool_t (CALLBACK *ENUM_TRIETREE_NODE)(const tchar_t* key, link_t_ptr nlk, void* p);

#ifdef	__cplusplus
extern "C" {
#endif

/***********************************************************************
@FUNCTION: create trie tree.
@INPUT: the character for seperating key sequence, eg: the '.' in '1.11.111'.
@RETURN: the link component of trie tree or NULL if failed.
***********************************************************************/
EXP_API link_t_ptr create_trie_tree(tchar_t kfeed);

/***********************************************************************
@FUNCTION: destroy trie tree.
@INPUT: the link component of trie tree.
@RETURN: none.
***********************************************************************/
EXP_API void destroy_trie_tree(link_t_ptr trie);

/***********************************************************************
@FUNCTION: add a pair of key-value into trie tree.
@INPUT: the link component of trie tree.
@INPUT: the key token.
@INPUT: the key token characters.
@INPUT: the value object.
@RETURN: the link component of node.
@NOTE: if the key exists in trie tree then the value object to be replaced,
	otherwise new key-value to be added.
***********************************************************************/
EXP_API link_t_ptr write_trie_node(link_t_ptr trie, const tchar_t* key, int len, object_t val);

/***********************************************************************
@FUNCTION: read object from trie tree.
@INPUT: the link component of trie tree.
@INPUT: the key token.
@INPUT: the key token characters.
@OUTPUT: the value object for returning content.
@RETURN: the link component of node if exists, otherwise return NULL.
@NOTE: if the key exists in trie tree then the value object to be copied.
***********************************************************************/
EXP_API link_t_ptr read_trie_node(link_t_ptr trie, const tchar_t* key, int len, object_t val);

/***********************************************************************
@FUNCTION: delete a pair of key-value in trie tree.
@INPUT: the link component of trie tree.
@INPUT: the key token.
@INPUT: the key token characters.
@RETURN: none.
@NOTE: if the key exists in trie tree then the key-value pair to be deleted.
***********************************************************************/
EXP_API void delete_trie_node(link_t_ptr trie, const tchar_t* key, int len);

/***********************************************************************
@FUNCTION: get a trie node by key.
@INPUT: the link component of trie tree.
@INPUT: the key token.
@INPUT: the key token characters.
@RETURN: the node link component for exists key, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_trie_node(link_t_ptr trie, const tchar_t* key, int len);

/***********************************************************************
@FUNCTION: get a trie tree by child node.
@INPUT: the node link component.
@RETURN: the trie tree link component.
***********************************************************************/
EXP_API link_t_ptr get_trie_from_node(link_t_ptr node);

/***********************************************************************
@FUNCTION: test a node is leaf node.
@INPUT: the node link component.
@RETURN: non-zero for leaf node.
***********************************************************************/
EXP_API bool_t is_trie_leaf(link_t_ptr node);

/***********************************************************************
@FUNCTION: enumerate nodes in trie tree.
@INPUT: the trie tree link component.
@INPUT: the enumerate callback function.
@INPUT: the param translate back to callback function.
@RETURN: the node component where enumerating break at.
@NOTE: the callback function called per node, when function return zero,
	the enmerating break.
***********************************************************************/
EXP_API link_t_ptr enum_trie_tree(link_t_ptr trie, ENUM_TRIETREE_NODE pf, void* param);

/***********************************************************************
@FUNCTION: get the node key token pointer.
@INPUT: the node link component.
@RETURN: key token pointer.
***********************************************************************/
EXP_API const tchar_t* get_trie_node_key_ptr(link_t_ptr node);

/***********************************************************************
@FUNCTION: copy the node key token content.
@INPUT: the node link component.
@OUTPUT: the string buffer.
@INPUT: the string buffer max characters, not include terminated-char.
@RETURN: the characters copyed.
***********************************************************************/
EXP_API int get_trie_node_key(link_t_ptr node, tchar_t* key, int max);

/***********************************************************************
@FUNCTION: set the node key token content.
@INPUT: the node link component.
@INPUT: the key token.
@INPUT: the token characters.
@RETURN: none.
***********************************************************************/
EXP_API void set_trie_node_key(link_t_ptr node, const tchar_t* key, int len);

/***********************************************************************
@FUNCTION: get the node value object pointer.
@INPUT: the node link component.
@RETURN: value object pointer.
***********************************************************************/
EXP_API const object_t get_trie_node_val_ptr(link_t_ptr node);

/***********************************************************************
@FUNCTION: copy the node value object content.
@INPUT: the node link component.
@OUTPUT: the value object for copying out.
@RETURN: none.
***********************************************************************/
EXP_API void get_trie_node_val(link_t_ptr node, object_t val);

/***********************************************************************
@FUNCTION: set the node value object content.
@INPUT: the node link component.
@INPUT: the value object for copying into.
@RETURN: none.
***********************************************************************/
EXP_API void set_trie_node_val(link_t_ptr node, object_t val);

/***********************************************************************
@FUNCTION: get the node extra data.
@INPUT: the node link component.
@RETURN: extra data if exists, otherwise return zero.
***********************************************************************/
EXP_API vword_t get_trie_node_delta(link_t_ptr node);

/***********************************************************************
@FUNCTION: set the node extra data.
@INPUT: the node link component.
@INPUT: the extra data.
@RETURN: none.
***********************************************************************/
EXP_API void set_trie_node_delta(link_t_ptr node, vword_t vw);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void trie_tree_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_TRIETREE_H*/
