/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc dicttable document

	@module	dicttable.h | interface file

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

#ifndef _DICTTABLE_H
#define _DICTTABLE_H

#include "../xdkdef.h"

typedef struct _dict_enum_t{
	int index;
	link_t_ptr dict;
	link_t_ptr entity;
}dict_enum_t;

typedef bool_t (CALLBACK *ENUM_DICTTABLE_ENTITY)(variant_t key, link_t_ptr nlk, void* p);

#ifdef	__cplusplus
extern "C" {
#endif

/***********************************************************************
@FUNCTION: create dictionary table.
@RETURN: the link component of dictionary table or NULL if failed.
***********************************************************************/
EXP_API link_t_ptr create_dict_table(void);

/***********************************************************************
@FUNCTION: destroy dictionary table.
@INPUT: the link component of dictionary table.
@RETURN: none.
***********************************************************************/
EXP_API void destroy_dict_table(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: copy source dictionary table to destination dictionary table.
@INPUT: the destination dictionary table link component.
@INPUT: the source dictionary table link component.
@RETURN: none.
***********************************************************************/
EXP_API void copy_dict_table(link_t_ptr ptr_dst, link_t_ptr ptr_src);

/***********************************************************************
@FUNCTION: clear the dictionary table.
@INPUT: the dictionary table link component.
@RETURN: none.
***********************************************************************/
EXP_API void clear_dict_table(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: get the dictionary entity by key.
@INPUT: the dictionary table link component.
@INPUT: the variant key.
@RETURN: the entity link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_dict_entity(link_t_ptr ptr, variant_t key);

/***********************************************************************
@FUNCTION: get the dictionary entity key reference.
@INPUT: the dictionary entity link component.
@RETURN: the variant key reference.
***********************************************************************/
EXP_API const variant_t get_dict_entity_key_ptr(link_t_ptr elk);

/***********************************************************************
@FUNCTION: copy the dictionary entity key variant.
@INPUT: the dictionary entity link component.
@OUTPUT: the variant for copying key variant.
@RETURN: none.
***********************************************************************/
EXP_API void get_dict_entity_key(link_t_ptr elk, variant_t key);

/***********************************************************************
@FUNCTION: replace the dictionary entity key variant.
@INPUT: the dictionary entity link component.
@INPUT: the new key variant.
@RETURN: none.
***********************************************************************/
EXP_API void set_dict_entity_key(link_t_ptr elk, variant_t key);

/***********************************************************************
@FUNCTION: get the dictionary entity value object struct.
@INPUT link_t_ptr elk: the dictionary entity link component.
@RETURN const object_t*: return the value object struct if exists, otherwise return NULL.
***********************************************************************/
EXP_API const object_t get_dict_entity_val_ptr(link_t_ptr elk);

/***********************************************************************
@FUNCTION: copy the dictionary entity value.
@INPUT: the dictionary entity link component.
@OUTPUT: the object for copying value object.
@RETURN: none.
***********************************************************************/
EXP_API void get_dict_entity_val(link_t_ptr elk, object_t val);

/***********************************************************************
@FUNCTION: replace the dictionary entity value object.
@INPUT: the dictionary entity link component.
@INPUT: the new value object to be copied into entiry.
@RETURN: none.
***********************************************************************/
EXP_API void set_dict_entity_val(link_t_ptr elk, object_t val);

/***********************************************************************
@FUNCTION: attach a value object to dictionary entity.
@INPUT: the dictionary entity link component.
@INPUT: the value object to be referenced by entity.
@RETURN: the original entity value object.
@NOTE: the val param can be NULL, the original entity value object returned,
	and entity value object cleaned.
***********************************************************************/
EXP_API object_t attach_dict_entity_val(link_t_ptr elk, object_t val);

/***********************************************************************
@FUNCTION: get the dictionary entity extract value.
@INPUT: the dictionary entity link component.
@RETURN: return extract value if exists, otherwise return zero.
***********************************************************************/
EXP_API vword_t get_dict_entity_delta(link_t_ptr elk);

/***********************************************************************
@FUNCTION: set the dictionary entity extract value.
@INPUT: the dictionary entity link component.
@INPUT: the extract value.
@RETURN: none.
***********************************************************************/
EXP_API void set_dict_entity_delta(link_t_ptr elk, vword_t val);

/***********************************************************************
@FUNCTION: enumerating the dictionary entites.
@INPUT: the dictionary table link component.
@INPUT: the callback function.
@INPUT: the parameter translate into callback function.
@RETURN: the entity link component breaking at, or NULL for not breaking.
@NOTE: the enumerating will be breaked when callback function return none zero,
	otherwise continue to all entites enumerated.
***********************************************************************/
EXP_API link_t_ptr	enum_dict_entity(link_t_ptr ptr, ENUM_DICTTABLE_ENTITY pf, void* pv);

/***********************************************************************
@FUNCTION: get the dictionary entites count.
@INPUT: the dictionary table link component.
@RETURN: return the count of entites.
***********************************************************************/
EXP_API int get_dict_entity_count(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: route to next dictionary entity using enumeration indicator.
@INOUTPUT: the dictionary eumeration indicator.
@RETURN: entity link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_dict_next_entity(dict_enum_t* pea);

/***********************************************************************
@FUNCTION: route to previous dictionary entity using enumeration indicator.
@INOUTPUT: the dictionary eumeration indicator.
@RETURN: entity link component if exists, otherwise return NULL.
***********************************************************************/
EXP_API link_t_ptr get_dict_prev_entity(dict_enum_t* pea);

/***********************************************************************
@FUNCTION: delete the dictionary entity by key variant.
@INPUT: the dictionary table link component.
@INPUT: the key variant.
@RETURN: none.
***********************************************************************/
EXP_API void delete_dict_entity(link_t_ptr ptr, variant_t key);

/***********************************************************************
@FUNCTION: write a key-value pair into the dictionary table.
@INPUT: the dictionary table link component.
@INPUT: the key variant.
@INPUT: the value object.
@RETURN: return the entity link component.
@NOTE: if the entity indicated by key is exists, the value of entity will be overwrited, 
	otherwise add a new entity with the key-value pair.
***********************************************************************/
EXP_API link_t_ptr write_dict_entity(link_t_ptr ptr, variant_t key, object_t val);

/***********************************************************************
@FUNCTION: read entity value object find by the key valiant.
@INPUT: the dictionary table link component.
@INPUT: the key variant.
@OUTPUT: the object for copying value object.
@RETURN: return nonzero if entity exists, otherwise return zero.
***********************************************************************/
EXP_API bool_t read_dict_entity(link_t_ptr ptr, variant_t key, object_t val);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void dict_table_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_DICTTABLE_H*/
