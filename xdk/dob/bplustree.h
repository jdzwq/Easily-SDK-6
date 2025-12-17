/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc B+ tree document

	@module	bplustree.h | interface file

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

#ifndef _BPLUSTREE_H
#define _BPLUSTREE_H

#include "../xdkdef.h"

/*enum bplus node callback function*/
typedef bool_t(CALLBACK *ENUM_BPLUSTREE_ENTITY)(variant_t key, object_t val, void* pv);

#ifdef	__cplusplus
extern "C" {
#endif

/***********************************************************************
@FUNCTION: create b+ tree.
@RETURN: the link component of b+tree or NULL if failed.
***********************************************************************/
EXP_API link_t_ptr create_bplus_tree(void);

/***********************************************************************
@FUNCTION: create b+ tree with index and data file table.
@INPUT: the link component of index file table.
@INPUT: the link component of data file table.
@RETURN: the link component of b+tree or NULL if failed.
***********************************************************************/
EXP_API link_t_ptr create_bplus_file_table(link_t_ptr index_table, link_t_ptr data_table);

/***********************************************************************
@FUNCTION: destroy b+ tree.
@INPUT: the link component of b+ tree.
@RETURN: none.
***********************************************************************/
EXP_API void destroy_bplus_tree(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: remove all child nodes of b+ tree.
@INPUT: the link component of b+ tree.
@RETURN: none.
***********************************************************************/
EXP_API void clear_bplus_tree(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: test for b+ tree.
@INPUT: the link component of b+ tree.
@RETURN: none-zero for b+ tree or zero for not.
***********************************************************************/
EXP_API bool_t is_bplus_tree(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: insert a key-value pair into b+ tree.
@INPUT: the link component of b+ tree.
@INPUT: the key identify.
@INPUT: the value object.
@RETURN: none-zero for success or zero for failed.
***********************************************************************/
EXP_API bool_t insert_bplus_entity(link_t_ptr ptr, variant_t key, object_t val);

/***********************************************************************
@FUNCTION: delete a key-value pair from b+ tree.
@INPUT: the link component of b+ tree.
@INPUT: the key identify.
@RETURN: none-zero for success or zero for failed.
***********************************************************************/
EXP_API bool_t delete_bplus_entity(link_t_ptr ptr, variant_t key);

/***********************************************************************
@FUNCTION: find a key-value pair from b+ tree.
@INPUT: the link component of b+ tree.
@INPUT: the key identify.
@OUTPUT: if finded, the val object holding the value content.
@RETURN: none-zero for success or zero for failed.
***********************************************************************/
EXP_API bool_t find_bplus_entity(link_t_ptr ptr, variant_t key, object_t val);

/***********************************************************************
@FUNCTION: enumerate the key-value pairs in b+ tree.
@INPUT: the link component of b+ tree.
@INPUT: the callback function for getting one key-value per called.
@INPUT: the user-parameter trans back to callback function.
@RETURN: none.
@NOTE: return non-zero in callback function will break the enumerating.
***********************************************************************/
EXP_API void enum_bplus_entity(link_t_ptr ptr, ENUM_BPLUSTREE_ENTITY pf, void* param);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void bplus_tree_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif


#endif /*_BPLUSTREE_H*/
