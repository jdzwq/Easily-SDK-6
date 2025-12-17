/***********************************************************************
	Easily SDK 6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc stringtable document

	@module	stringtable.h | interface file

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

#ifndef _STRTABLE_H
#define _STRTABLE_H

#include "../xdkdef.h"

/**********************************************************************/
#define set_string_entity_dirty(elk,c)		set_string_entity_mask(elk,(get_string_entity_mask(elk) & 0xFFFFFFF0) | c)

#define get_string_entity_dirty(elk)		(get_string_entity_mask(elk) & 0x0000000F)
/**********************************************************************/
#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************************************
@FUNCTION: create a string table.
@INPUT: sort rule 1: ascend,-1: descend, 0: none.
@RETURN: return the string table link component.
***********************************************************************/
EXP_API link_t_ptr create_string_table(int order);

/**********************************************************************
@FUNCTION: destroy a string table.
@INPUT: the string table link component.
@RETURN: none.
***********************************************************************/
EXP_API void destroy_string_table(link_t_ptr ptr);

/**********************************************************************
@FUNCTION: delete all string entities.
@INPUT: the string table link component.
@RETURN: none.
***********************************************************************/
EXP_API void clear_string_table(link_t_ptr ptr);

/**********************************************************************
@FUNCTION: test is string table.
@INPUT: the string table link component.
@RETURN: return nonzero for being a string table, otherwise return zero.
***********************************************************************/
EXP_API bool_t is_string_table(link_t_ptr ptr);

/**********************************************************************
@FUNCTION: test is string table child entity.
@INPUT: the string table link component.
@INPUT: the string entity link component.
@RETURN: return nonzero for being a string entity.
***********************************************************************/
EXP_API bool_t is_string_entity(link_t_ptr ptr, link_t_ptr ilk);

/**********************************************************************
@FUNCTION: get string table entities.
@INPUT: the string table link component.
@RETURN: return the count of string entities.
***********************************************************************/
EXP_API int get_string_entity_count(link_t_ptr ptr);

/**********************************************************************
@FUNCTION: add string entity into string table, if the key exists in string table, 
	the value will be replaced.
@INPUT: the string table link component.
@INPUT: the key stirng token.
@INPUT: the key token length in characters.
@INPUT: the value stirng token.
@INPUT: the value token length in characters.
@RETURN: return string entity link component.
***********************************************************************/
EXP_API link_t_ptr write_string_entity(link_t_ptr ptr, const tchar_t* key, int keylen, const tchar_t* val, int vallen);

/**********************************************************************
@FUNCTION: read string entity value from string table by key.
@INPUT: the string table link component.
@INPUT: the key stirng token.
@INPUT: the key token length in characters.
@OUTPUT: the stirng buffer for returning value.
@INPUT: the value string buffer size in characters.
@RETURN: return entity value length in characters.
***********************************************************************/
EXP_API int read_string_entity(link_t_ptr ptr, const tchar_t* key, int keylen, tchar_t* buf, int max);

/**********************************************************************
@FUNCTION: get string entity value string pointer.
@INPUT: the string table link component.
@INPUT: the key stirng token.
@INPUT: the key token length in characters.
@RETURN: return entity value string pointer if exists, otherwise return NULL.
***********************************************************************/
EXP_API const tchar_t* get_string_entity_ptr(link_t_ptr ptr, const tchar_t* key, int keylen);

/**********************************************************************
@FUNCTION: find the string entity by key.
@INPUT: the string table link component.
@INPUT: the key stirng token.
@INPUT: the key token length in characters.
@RETURN: return string entity link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_string_entity(link_t_ptr ptr, const tchar_t* key, int keylen);

/**********************************************************************
@FUNCTION: NOCASE find the string entity by key.
@INPUT: the string table link component.
@INPUT: the key stirng token.
@INPUT: the key token length in characters.
@RETURN: return string entity link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr	find_string_entity(link_t_ptr ptr, const tchar_t* key, int keylen);

/**********************************************************************
@FUNCTION: insert the string entity after the position.
@INPUT: the string table link component.
@INPUT: the position link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN: return new string entity link component.
***********************************************************************/
EXP_API link_t_ptr insert_string_entity(link_t_ptr ptr, link_t_ptr pos);

/**********************************************************************
@FUNCTION: delete the string entity.
@INPUT: the string table link component.
@INPUT: the link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN: none.
***********************************************************************/
EXP_API void delete_string_entity(link_t_ptr ptr, link_t_ptr pos);

/**********************************************************************
@FUNCTION: get the string entity key string pointer.
@INPUT: the string entity link component.
@RETURN: the key string pointer.
***********************************************************************/
EXP_API const tchar_t* get_string_entity_key_ptr(link_t_ptr elk);

/**********************************************************************
@FUNCTION: copy the string entity key.
@INPUT: the string entity link component.
@OUTPUT: the string buffer for returning key token.
@INPUT: the string buffer size in characters.
@RETURN: return characters copyed.
***********************************************************************/
EXP_API int get_string_entity_key(link_t_ptr elk, tchar_t* buf, int max);

/**********************************************************************
@FUNCTION: set the string entity key.
@INPUT: the string entity link component.
@INPUT: the key string token.
@INPUT: the key token length in characters.
@RETURN: none.
***********************************************************************/
EXP_API void set_string_entity_key(link_t_ptr elk, const tchar_t* key, int keylen);

/**********************************************************************
@FUNCTION: get the string entity value string pointer.
@INPUT: the string entity link component.
@RETURN: the value string pointer.
***********************************************************************/
EXP_API const tchar_t* get_string_entity_val_ptr(link_t_ptr elk);

/**********************************************************************
@FUNCTION: copy the string entity value.
@INPUT: the string entity link component.
@OUTPUT: the string buffer for returning value token.
@INPUT: the string buffer size in characters.
@RETURN: return characters copyed.
***********************************************************************/
EXP_API int get_string_entity_val(link_t_ptr elk, tchar_t* buf, int max);

/**********************************************************************
@FUNCTION: set the string entity value.
@INPUT: the string entity link component.
@INPUT: the value string token.
@INPUT: the value token length in characters.
@RETURN: none.
***********************************************************************/
EXP_API void set_string_entity_val(link_t_ptr elk,const tchar_t* val,int vallen);

/**********************************************************************
@FUNCTION: set the string entity extract data.
@INPUT: the string entity link component.
@INPUT: the extract data.
@RETURN: none.
***********************************************************************/
EXP_API void set_string_entity_delta(link_t_ptr elk, vword_t data);

/**********************************************************************
@FUNCTION: get the string entity extract data.
@INPUT: the string entity link component.
@RETURN: return the extract data.
***********************************************************************/
EXP_API vword_t get_string_entity_delta(link_t_ptr elk);

/**********************************************************************
@FUNCTION: set the string entity mask.
@INPUT: the string entity link component.
@INPUT: the mask value.
@RETURN: none.
***********************************************************************/
EXP_API void set_string_entity_mask(link_t_ptr elk, dword_t mask);

/**********************************************************************
@FUNCTION: get the string entity mask.
@INPUT: the string entity link component.
@RETURN: return the mask value.
***********************************************************************/
EXP_API dword_t get_string_entity_mask(link_t_ptr elk);

/**********************************************************************
@FUNCTION: get the next string entity.
@INPUT: the string table link component.
@INPUT: the entity link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN: return the entity link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_string_next_entity(link_t_ptr ptr,link_t_ptr pos);

/**********************************************************************
@FUNCTION: get the previous string entity.
@INPUT: the string table link component.
@INPUT: the entity link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN: return the entity link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_string_prev_entity(link_t_ptr ptr,link_t_ptr pos);

/**********************************************************************
@FUNCTION: get the previous string entity at position.
@INPUT: the string table link component.
@INPUT: the zero based position.
@RETURN: return the entity link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_string_entity_at(link_t_ptr ptr, int index);

/**********************************************************************
@FUNCTION: calc the string entity position.
@INPUT: the string table link component.
@INPUT: the string entity link component.
@RETURN: return zero based position.
***********************************************************************/
EXP_API int get_string_entity_index(link_t_ptr ptr, link_t_ptr elk);

/**********************************************************************
@FUNCTION: get the dirty string entity count.
@INPUT: the string table link component.
@RETURN: return count of entities.
***********************************************************************/
EXP_API int get_string_updated_entity_count(link_t_ptr ptr);

/**********************************************************************
@FUNCTION: parse string table from attributes set.
@INPUT: the string table link component.
@INPUT: the attributes set string token.
@INPUT: the length of attribytes string token.
@RETURN: none.
***********************************************************************/
EXP_API void string_table_parse_attrset(link_t_ptr ptr,const tchar_t* attrset,int len);

/**********************************************************************
@FUNCTION: format string table to attributes set.
@INPUT: the string table link component.
@OUTPUT: the string buffer for returning attributes set token.
@INPUT: the string buffer size in characters.
@RETURN: return the characters formated.
***********************************************************************/
EXP_API int string_table_format_attrset(link_t_ptr ptr,tchar_t* buf,int max);

/**********************************************************************
@FUNCTION: format string entities key to set.
@INPUT: the string table link component.
@OUTPUT: the string buffer for returning keys set token.
@INPUT: the string buffer size in characters.
@INPUT: the seperator character.
@RETURN: return the characters formated.
***********************************************************************/
EXP_API int string_table_format_key_tokens(link_t_ptr ptr, tchar_t* buf, int max, tchar_t feed);

/**********************************************************************
@FUNCTION: format string entities value to set.
@INPUT: the string table link component.
@OUTPUT: the string buffer for returning values set token.
@INPUT: the string buffer size in characters.
@INPUT: the seperator character.
@RETURN: return the characters formated.
***********************************************************************/
EXP_API int string_table_format_val_tokens(link_t_ptr ptr, tchar_t* buf, int max, tchar_t feed);

/**********************************************************************
@FUNCTION: parse string table entities from options set.
@INPUT: the string table link component.
@INPUT: the options set string token.
@INPUT: the length of options string token.
@INPUT: the item seperator character.
@INPUT: the line seperator character.
@RETURN: return count of entities parsed.
***********************************************************************/
EXP_API int string_table_parse_options(link_t_ptr ptr, const tchar_t* str, int len, tchar_t itemfeed, tchar_t linefeed);

/**********************************************************************
@FUNCTION: format string table entities to options set.
@INPUT: the string table link component.
@OUTPUT: the string buffer for return options set.
@INPUT: the string buffer size in characters.
@INPUT: the item seperator character.
@INPUT: the line seperator character.
@RETURN: return characters formated.
***********************************************************************/
EXP_API int string_table_format_options(link_t_ptr ptr, tchar_t* buf, int max, tchar_t itemfeed, tchar_t linefeed);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void string_table_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif //_STRTABLE_H
