/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc wordstable document

	@module	wordstable.h | interface file

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

#ifndef _WORDSTABLE_H
#define _WORDSTABLE_H

#include "../xdkdef.h"

/***********************************************************************/
#define set_words_item_hidden(ilk, b)		set_words_item_delta(ilk, (vword_t)b)

#define get_words_item_hidden(ilk)			(bool_t)get_words_item_delta(ilk)
/***********************************************************************/

#ifdef	__cplusplus
extern "C" {
#endif

/***********************************************************************
@FUNCTION: create a words table.
@INPUT: sort rule 1: ascend,-1: descend, 0: none.
@RETURN: the link component of words table or NULL if failed.
***********************************************************************/
EXP_API link_t_ptr create_words_table(int order);

/***********************************************************************
@FUNCTION: destroy the words table.
@INPUT: the link component of words table.
@RETURN: none.
***********************************************************************/
EXP_API void destroy_words_table(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: clear all items in words table.
@INPUT: the link component of words table.
@RETURN: none.
***********************************************************************/
EXP_API void clear_words_table(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: test is words table.
@INPUT: the link component.
@RETURN: none-zero for true.
***********************************************************************/
EXP_API bool_t is_words_table(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: test is words item.
@INPUT: the link component of words table.
@INPUT: the link component of words item.
@RETURN: none-zero for true.
***********************************************************************/
EXP_API bool_t is_words_item(link_t_ptr ptr, link_t_ptr ilk);

/***********************************************************************
@FUNCTION: get words item count in table.
@INPUT: the link component of words table.
@RETURN: words items.
***********************************************************************/
EXP_API int get_words_item_count(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: insert words item into table.
@INPUT: the link component of words table.
@INPUT: the item token.
@INPUT: the item token characters.
@RETURN: the link component of words items.
***********************************************************************/
EXP_API link_t_ptr insert_words_item(link_t_ptr ptr, const tchar_t* val, int len);

/***********************************************************************
@FUNCTION: find words item by value.
@INPUT: the link component of words table.
@INPUT: the item token.
@INPUT: the item token characters.
@RETURN: the link component of words items if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_words_item(link_t_ptr ptr, const tchar_t* val, int len);

/***********************************************************************
@FUNCTION: delete words item or by indicator.
@INPUT: the link component of words table.
@INPUT: the link component of words item, or LINK_FIEST, LINK_LAST indicator.
@RETURN: none.
***********************************************************************/
EXP_API void delete_words_item(link_t_ptr ptr, link_t_ptr pos);

/***********************************************************************
@FUNCTION: get words item value pointer.
@INPUT: the link component of words item.
@RETURN: the value pointer.
***********************************************************************/
EXP_API const tchar_t* get_words_item_text_ptr(link_t_ptr ilk);

/***********************************************************************
@FUNCTION: set words item extra data.
@INPUT: the link component of words item.
@RETURN: none.
***********************************************************************/
EXP_API void set_words_item_delta(link_t_ptr ilk, vword_t data);

/***********************************************************************
@FUNCTION: get words item extra data.
@INPUT: the link component of words item.
@RETURN: var long data.
***********************************************************************/
EXP_API vword_t get_words_item_delta(link_t_ptr ilk);

/***********************************************************************
@FUNCTION: get next words item by current item or indicator.
@INPUT: the link component of words item, or LINK_FIEST, LINK_LAST indicator.
@RETURN: the link component of words item if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_words_next_item(link_t_ptr ptr,link_t_ptr pos);

/***********************************************************************
@FUNCTION: get prior words item by current item or indicator.
@INPUT: the link component of words item, or LINK_FIEST, LINK_LAST indicator.
@RETURN: the link component of words item if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_words_prev_item(link_t_ptr ptr,link_t_ptr pos);

/***********************************************************************
@FUNCTION: get next visible words item by current item or indicator.
@INPUT: the link component of words item, or LINK_FIEST, LINK_LAST indicator.
@RETURN: the link component of words item if exists, otherwise return NULL.
@NOTE: if set_words_item_hidden called on thar words item, cause it to be hiddened.
***********************************************************************/
EXP_API link_t_ptr get_words_next_visible_item(link_t_ptr ptr, link_t_ptr pos);

/***********************************************************************
@FUNCTION: get next visible words item by current item or indicator.
@INPUT: the link component of words item, or LINK_FIEST, LINK_LAST indicator.
@RETURN: the link component of words item if exists, otherwise return NULL.
@NOTE: if set_words_item_hidden called on thar words item, cause it to be hiddened.
***********************************************************************/
EXP_API link_t_ptr get_words_prev_visible_item(link_t_ptr ptr, link_t_ptr pos);

/***********************************************************************
@FUNCTION: get visible words item count in words table.
@INPUT: the link component of words table
@RETURN: the visible items.
***********************************************************************/
EXP_API int get_words_visible_item_count(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: parse words item from string token.
@INPUT: the link component of words table.
@INPUT: the string tokens.
@INPUT: the string tokens characters.
@INPUT: the character for seperating items.
@RETURN: none.
***********************************************************************/
EXP_API void words_table_parse_tokens(link_t_ptr ptr,const tchar_t* tokens,int len,tchar_t feed);

/***********************************************************************
@FUNCTION: format words item to string buffer.
@INPUT: the link component of words table.
@INPUT: the string buffer.
@INPUT: the string buffer max characters.
@INPUT: the character for seperating items.
@RETURN: characters formated in buffer.
***********************************************************************/
EXP_API int words_table_format_tokens(link_t_ptr ptr,tchar_t* buf,int max,tchar_t feed);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void words_table_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif //_WORDSTABLE_H
