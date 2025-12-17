/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc hashtable document

	@module	hashtable.h | interface file

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

#ifndef _HASHTABLE_H
#define _HASHTABLE_H

#include "../xdkdef.h"

typedef struct _hash_enum_t{
	int index;
	link_t_ptr hash;
	link_t_ptr entity;
}hash_enum_t;

#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************************************
@FUNCTION: create a hash table.
@RETURN: return the hash table link component.
***********************************************************************/
EXP_API link_t_ptr create_hash_table(void);

/**********************************************************************
@FUNCTION: destroy a hash table.
@INPUT: the hash table link component.
@RETURN: none.
***********************************************************************/
EXP_API void destroy_hash_table(link_t_ptr ptr);

/**********************************************************************
@FUNCTION: copy source hash table to destination hash table.
@INPUT: the destination hash table link component.
@INPUT: the source hash table link component.
@RETURN: none.
***********************************************************************/
EXP_API void copy_hash_table(link_t_ptr ptr_dst, link_t_ptr ptr_src);

/**********************************************************************
@FUNCTION: clear a hash table, all entities will be deleted.
@INPUT: the hash table link component.
@RETURN: none.
***********************************************************************/
EXP_API void clear_hash_table(link_t_ptr ptr);

/**********************************************************************
@FUNCTION delete_hash_entity: delete a hash entity.
@INPUT link_t_ptr elk: the hash entity link component.
@RETURN void: none.
***********************************************************************/
EXP_API void delete_hash_entity(link_t_ptr elk);

/**********************************************************************
@FUNCTION: get a hash entity by key.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the key token length in characters.
@RETURN: return the hash entity link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_hash_entity(link_t_ptr ptr, const tchar_t* key, int keylen);

/**********************************************************************
@FUNCTION: get a hash entity key string pointer.
@INPUT: the hash entity link component.
@RETURN: return the hash entity key token pointer.
***********************************************************************/
EXP_API const tchar_t* get_hash_entity_key_ptr(link_t_ptr elk);

/**********************************************************************
@FUNCTION: get a hash entity value string pointer.
@INPUT: the hash entity link component.
@RETURN: return the hash entity value token pointer.
***********************************************************************/
EXP_API const tchar_t* get_hash_entity_val_ptr(link_t_ptr elk);

/**********************************************************************
@FUNCTION: copy the hash entity key string.
@INPUT: the hash entity link component.
@INPUT: the string buffer.
@INPUT: the string buffer maximized size, not inlude terminate character.
@RETURN: return the hash entity key token length in characters.
***********************************************************************/
EXP_API int get_hash_entity_key(link_t_ptr elk, tchar_t* buf, int max);

/**********************************************************************
@FUNCTION: copy the hash entity value string.
@INPUT: the hash entity link component.
@INPUT: the string buffer.
@INPUT: the string buffer maximized size, not inlude terminate character.
@RETURN: return the hash entity value token length in characters.
***********************************************************************/
EXP_API int get_hash_entity_val(link_t_ptr elk, tchar_t* buf, int max);

/**********************************************************************
@FUNCTION: set the hash entity extract data.
@INPUT: the hash entity link component.
@INPUT: the extract data.
@RETURN: none.
***********************************************************************/
EXP_API void set_hash_entity_delta(link_t_ptr elk, vword_t data);

/**********************************************************************
@FUNCTION: get the hash entity extract data.
@INPUT: the hash entity link component.
@RETURN: return the hash entity extract data.
***********************************************************************/
EXP_API vword_t get_hash_entity_delta(link_t_ptr elk);

/**********************************************************************
@FUNCTION: attach a value buffer to the hash entity.
@INPUT: the hash entity link component.
@INPUT: the value string buffer.
@RETURN: none.
***********************************************************************/
EXP_API void attach_hash_entity_val(link_t_ptr elk, tchar_t* val);

/**********************************************************************
@FUNCTION: detach a value buffer from the hash entity.
@INPUT: the hash entity link component.
@RETURN: return the value string buffer if exists, otherwise return NULL.
***********************************************************************/
EXP_API tchar_t* detach_hash_entity_val(link_t_ptr elk);

/**********************************************************************
@FUNCTION: enum hash entities.
@INPUT: the hash table link component.
@INPUT: the callback function, if the function return zero, the enumeration will be breaked.
@INPUT: the param translated into callback function.
@RETURN: return the count of enumerated hash entity.
***********************************************************************/
EXP_API int	enum_hash_entity(link_t_ptr ptr, PF_ENUMLINK pf, void* pv);

/**********************************************************************
@FUNCTION: counting hash entities.
@INPUT: the hash table link component.
@INPUT: the callback function, if the function return zero, the enumeration will be breaked.
@INPUT: the param translated into callback function.
@RETURN: return the count of enumerated hash entity.
***********************************************************************/
EXP_API int get_hash_entity_count(link_t_ptr ptr);

/**********************************************************************
@FUNCTION: get hash entity at posotion.
@INPUT: the hash table link component.
@INPUT: the zero based position.
@RETURN: return hash entity link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_hash_entity_at(link_t_ptr ptr, int index);

/**********************************************************************
@FUNCTION: get hash entity posotion.
@INPUT: the hash table link component.
@INPUT: the hash entity link component.
@RETURN: return zero based position if entity inside table, otherwise return -1.
***********************************************************************/
EXP_API int get_hash_entity_index(link_t_ptr ptr, link_t_ptr elk);

/**********************************************************************
@FUNCTION: get next hash entity.
@INPUT: the hash enumertor struct.
@RETURN: return entity link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_hash_next_entity(hash_enum_t* pea);

/**********************************************************************
@FUNCTION: get previous hash entity.
@INPUT: the hash enumertor struct.
@RETURN: return entity link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_hash_prev_entity(hash_enum_t* pea);

/**********************************************************************
@FUNCTION: delete the hash entity by key.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the key string token length in characters.
@RETURN: none.
***********************************************************************/
EXP_API void delete_hash_attr(link_t_ptr ptr, const tchar_t* key, int keylen);

/**********************************************************************
@FUNCTION: write a hash key and value into hash table,
	if the key exists in hash table, the entity will be overwrited, 
	else a new entity will be inserted.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the key string token length in characters.
@INPUT: the value string token.
@INPUT: the value string token length in characters.
@RETURN: the hash entity link componet.
***********************************************************************/
EXP_API link_t_ptr write_hash_attr(link_t_ptr ptr, const tchar_t* key, int keylen, const tchar_t* val, int vallen);

/**********************************************************************
@FUNCTION: read hash value from hash table by key.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the key string token length in characters.
@OUTPUT: the string buffer for returning value.
@INPUT: the string buffer length in characters, not include terminate character.
@RETURN: return the hash entity value length in characters if exists, otherwise return zero.
***********************************************************************/
EXP_API int read_hash_attr(link_t_ptr ptr, const tchar_t* key, int keylen, tchar_t* buf, int max);

/**********************************************************************
@FUNCTION: get hash value string pointer from hash table by key.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the key string token length in characters.
@RETURN: return the hash entity value string pointer if exists, otherwise return NULL.
***********************************************************************/
EXP_API const tchar_t* get_hash_attr_ptr(link_t_ptr ptr, const tchar_t* key, int keylen);

/**********************************************************************
@FUNCTION: get hash value token length from hash table by key.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the key string token length in characters.
@RETURN: return the hash entity value token length in characters if exists, otherwise return zero.
***********************************************************************/
EXP_API int get_hash_attr_len(link_t_ptr ptr, const tchar_t* key, int keylen);

/**********************************************************************
@FUNCTION: set hash entity a boolean value.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the boolean value.
@RETURN: the hash entity link componet.
***********************************************************************/
EXP_API link_t_ptr set_hash_attr_boolean(link_t_ptr ptr, const tchar_t* key, bool_t b);

/**********************************************************************
@FUNCTION: get hash entity boolean value.
@INPUT: the hash table link component.
@INPUT: the key string token.
@RETURN: return the hash entity boolean value if exists, otherwise return zero.
***********************************************************************/
EXP_API bool_t get_hash_attr_boolean(link_t_ptr ptr, const tchar_t* key);

/**********************************************************************
@FUNCTION: set hash entity a integer value.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the integer value.
@RETURN: the hash entity link componet.
***********************************************************************/
EXP_API link_t_ptr set_hash_attr_integer(link_t_ptr ptr, const tchar_t* key, int ul);

/**********************************************************************
@FUNCTION: get hash entity integer value.
@INPUT: the hash table link component.
@INPUT: the key string token.
@RETURN: return the hash entity integer value if exists, otherwise return zero.
***********************************************************************/
EXP_API int get_hash_attr_integer(link_t_ptr ptr, const tchar_t* key);

/**********************************************************************
@FUNCTION: set hash entity a float value.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the float value.
@RETURN: the hash entity link componet.
***********************************************************************/
EXP_API link_t_ptr set_hash_attr_float(link_t_ptr ptr, const tchar_t* key, float f);

/**********************************************************************
@FUNCTION: get hash entity float value.
@INPUT: the hash table link component.
@INPUT: the key string token.
@RETURN: return the hash entity float value if exists, otherwise return zero.
***********************************************************************/
EXP_API float get_hash_attr_float(link_t_ptr ptr, const tchar_t* key);

/**********************************************************************
@FUNCTION: set hash entity a double value.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the double value.
@RETURN: the hash entity link componet.
***********************************************************************/
EXP_API link_t_ptr set_hash_attr_numeric(link_t_ptr ptr, const tchar_t* key, double db);

/**********************************************************************
@FUNCTION: get hash entity double value.
@INPUT: the hash table link component.
@INPUT: the key string token.
@RETURN: return the hash entity double value if exists, otherwise return zero.
***********************************************************************/
EXP_API double get_hash_attr_numeric(link_t_ptr ptr, const tchar_t* key);

/**********************************************************************
@FUNCTION: write a hash key and bytes value into hash table,
	if the key exists in hash table, the entity will be overwrited, 
	else a new entity will be inserted.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the key string token length in characters.
@INPUT: the bytes value buffer.
@INPUT: the buffer size in bytes.
@RETURN: the hash entity link componet.
***********************************************************************/
EXP_API link_t_ptr write_hash_bytes(link_t_ptr ptr, const tchar_t* key, int keylen, const byte_t* val, dword_t vallen);

/**********************************************************************
@FUNCTION: read hash bytes value from hash table by key.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the key string token length in characters.
@OUTPUT: the bytes buffer for returning value.
@INPUT: the buffer size in bytes.
@RETURN: return the hash entity value size in bytes if exists, otherwise return zero.
***********************************************************************/
EXP_API dword_t read_hash_bytes(link_t_ptr ptr, const tchar_t* key, int keylen, byte_t* buf, dword_t max);

/**********************************************************************
@FUNCTION: get hash value bytes buffer pointer from hash table by key.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the key string token length in characters.
@RETURN: return the hash entity value bytes buffer pointer if exists, otherwise return NULL.
***********************************************************************/
EXP_API const byte_t* get_hash_bytes_ptr(link_t_ptr ptr, const tchar_t* key, int keylen);

/**********************************************************************
@FUNCTION: get hash value bytes size from hash table by key.
@INPUT: the hash table link component.
@INPUT: the key string token.
@INPUT: the key string token length in characters.
@RETURN: return the hash entity value size in bytes if exists, otherwise return zero.
***********************************************************************/
EXP_API dword_t get_hash_bytes_size(link_t_ptr ptr, const tchar_t* key, int keylen);

/**********************************************************************
@FUNCTION: get a hash entity value bytes buffer pointer.
@INPUT: the hash entity link component.
@RETURN: return the hash entity value bytes buffer pointer.
***********************************************************************/
EXP_API const byte_t* get_hash_entity_bytes_ptr(link_t_ptr elk);

/**********************************************************************
@FUNCTION: get a hash entity value size in bytes.
@INPUT: the hash entity link component.
@RETURN: return the hash entity size in bytes.
***********************************************************************/
EXP_API dword_t get_hash_entity_bytes_size(link_t_ptr elk);

/**********************************************************************
@FUNCTION: attach bytes buffer to hash entity.
@INPUT: the hash entity link component.
@INPUT: the bytes buffer.
@INPUT: the buffer value size in bytes.
@RETURN: none.
***********************************************************************/
EXP_API void attach_hash_entity_bytes(link_t_ptr elk, byte_t* val, dword_t len);

/**********************************************************************
@FUNCTION: detach bytes buffer from hash entity.
@INPUT: the hash entity link component.
@RETURN: return the bytes buffer if exists, otherwise return NULL.
***********************************************************************/
EXP_API byte_t* detach_hash_entity_bytes(link_t_ptr elk);

/**********************************************************************
@FUNCTION: replace characters in hash entity string value at position.
@INPUT: the hash entity link component.
@INPUT: the key string token used to find entity.
@INPUT: the zero based position for string buffer replacing.
@INPUT: the character array.
@INPUT: the count of characters.
@RETURN: return hash entity string token if exists, otherwise return NULL.
***********************************************************************/
EXP_API const tchar_t* hash_attr_set_chars(link_t_ptr elk, const tchar_t* key, int pos, const tchar_t* pch, int n);

/**********************************************************************
@FUNCTION: insert characters into hash entity string value at position.
@INPUT: the hash entity link component.
@INPUT: the key string token used to find entity.
@INPUT: the zero based position for string buffer inserting.
@INPUT: the character array.
@INPUT: the count of characters.
@RETURN: return hash entity string token if exists, otherwise return NULL.
***********************************************************************/
EXP_API const tchar_t* hash_attr_ins_chars(link_t_ptr elk, const tchar_t* key, int pos, const tchar_t* pch, int n);

/**********************************************************************
@FUNCTION: delete some characters from hash entity string value at position.
@INPUT: the hash entity link component.
@INPUT: the key string token used to find entity.
@INPUT: the zero based position for string buffer inserting.
@INPUT: the count of characters.
@RETURN: return hash entity string token if exists, otherwise return NULL.
***********************************************************************/
EXP_API const tchar_t* hash_attr_del_chars(link_t_ptr elk, const tchar_t* key, int pos, int n);

/**********************************************************************
@FUNCTION: pare hash table from attributes set.
@INPUT: the hash entity link component.
@INPUT: the attributes set. it like "key1=val1;key2=val2;...".
@INPUT: the length of attributes token in characters.
@RETURN: none.
***********************************************************************/
EXP_API void hash_table_parse_attrset(link_t_ptr ptr, const tchar_t* attrset, int len);

/**********************************************************************
@FUNCTION: format hash table to attributes set.
@INPUT: the hash entity link component.
@OUTPUT: the attributes set buffer, the output string token like: "key1=val1;key2=val2;...".
@INPUT: the size of attributes set buffer in characters, not include terminate character.
@RETURN: return the length of formated token.
***********************************************************************/
EXP_API int hash_table_format_attrset(link_t_ptr ptr, tchar_t* buf, int max);

/**********************************************************************
@FUNCTION: pare hash table from options set.
@INPUT: the hash entity link component.
@INPUT: the options string token. it like "key1~val1;key2~val2;...".
@INPUT: the length of options token in characters.
@INPUT: the item seperator character. it like "~".
@INPUT: the line seperator character. it like ";".
@RETURN: return count of item parsed.
***********************************************************************/
EXP_API int hash_table_parse_options(link_t_ptr ptr, const tchar_t* str, int len, tchar_t itemfeed, tchar_t linefeed);

/**********************************************************************
@FUNCTION: format hash table to options set.
@INPUT: the hash entity link component.
@INPUT: the options string buffer, the output token will like "key1~val1;key2~val2;...".
@INPUT: the size of options buffer in characters.
@INPUT: the item seperator character. it like "~".
@INPUT: the line seperator character. it like ";".
@RETURN: return length of string formated in characters.
***********************************************************************/
EXP_API int hash_table_format_options(link_t_ptr ptr, tchar_t* buf, int max, tchar_t itemfeed, tchar_t linefeed);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void hash_table_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_HASHTABLE_H*/
