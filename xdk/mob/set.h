/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdm set document

	@module	set.h | interface file

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

#ifndef _SET_H
#define _SET_H

#include "../xdkdef.h"

typedef enum{
	_SET_SET = 0,
	_SET_ELE = 1
}SET_TYPE;

typedef struct _set_t* set_t_ptr;

typedef struct _set_t{
	int type;
	int size;
	union{
		double data;
		set_t_ptr pset;
	};
}set_t;

#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************************************
@FUNCTION: alloc a empty set.
@RETURN: set object.
***********************************************************************/
EXP_API set_t* set_alloc(void);

/**********************************************************************
@FUNCTION: free the set.
@INPUT: the set object.
@RETURN: none.
***********************************************************************/
EXP_API void set_free(set_t* pset);

/**********************************************************************
@FUNCTION: test set is empty.
@INPUT: the set object.
@RETURN: none zero if empty set, otherwise return zero.
***********************************************************************/
EXP_API bool_t set_is_empty(set_t* pset);

/**********************************************************************
@FUNCTION: copy set from source set.
@INPUT: the destination set object.
@INPUT: the source set object.
@RETURN: none.
***********************************************************************/
EXP_API void set_copy(set_t* pdst, const set_t* psrc);

/**********************************************************************
@FUNCTION: compare two set.
@INPUT: the set object.
@INPUT: the set object.
@RETURN: -1 for p1 < p2, 0 for p1 = p2, 1 for p1 > p2.
@NOTE: equal if two set have same elements and child sets.
***********************************************************************/
EXP_API int set_comp(const set_t* p1, const set_t* p2);

/**********************************************************************
@FUNCTION: clear set contents.
@INPUT: the set object.
@RETURN: none.
***********************************************************************/
EXP_API void set_clear(set_t* pset);

/**********************************************************************
@FUNCTION: merge two set contents.
@INPUT: the destination set object.
@INPUT: the sub set object.
@RETURN: none.
@NOTE: if sub set in destination set, NOP.
***********************************************************************/
EXP_API void set_add(set_t* pset, const set_t* psub);

/**********************************************************************
@FUNCTION: delete sub set from destination.
@INPUT: the destination set object.
@INPUT: the sub set object.
@RETURN: none.
@NOTE: if sub set not in destination set, NOP.
***********************************************************************/
EXP_API void set_del(set_t* pset, const set_t* psub);

/**********************************************************************
@FUNCTION: test sub set if in destination.
@INPUT: the destination set object.
@INPUT: the sub set object.
@RETURN: none zero for exists, otherwise return zero.
***********************************************************************/
EXP_API bool_t set_in(set_t* pset, const set_t* psub);

/**********************************************************************
@FUNCTION: get element count in set.
@INPUT: the set object.
@RETURN: elements.
***********************************************************************/
EXP_API int set_count(set_t* pset);

/**********************************************************************
@FUNCTION: get sub element or set.
@INPUT: the set object.
@INPUT: the zero-based index.
@RETURN: none.
***********************************************************************/
EXP_API void set_get(set_t* pset, int index, set_t* psub);

/**********************************************************************
@FUNCTION: parse set from string token.
@INPUT: the set object.
@INPUT: the string token.
@INPUT: the string characters.
@RETURN: none.
***********************************************************************/
EXP_API void set_parse(set_t* pset, const tchar_t* token, int len);

/**********************************************************************
@FUNCTION: format set to string token.
@INPUT: the set object.
@INPUT: the string buffer.
@INPUT: the buffer characters, not include zero-terminated.
@RETURN: characters copied.
***********************************************************************/
EXP_API int set_format(const set_t* pset, tchar_t* buf, int max);

/**********************************************************************
@FUNCTION: encode set to bytes sequence.
@INPUT: the set object.
@INPUT: the bytes buffer for encoding.
@RETURN: bytes encoded, zero for failed.
@NOTE: buffer can be NULL for testing how many bytes will be encoded.
***********************************************************************/
EXP_API dword_t set_encode(const set_t* pset, byte_t* buf);

/**********************************************************************
@FUNCTION: decode set from bytes sequence.
@INPUT: the set object.
@INPUT: the bytes buffer.
@RETURN: bytes decoded, zero for failed.
@NOTE: set be NULL for testing how many bytes will be decoded.
***********************************************************************/
EXP_API dword_t set_decode(set_t* pset, const byte_t* buf);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void set_self_test();
#endif

#ifdef	__cplusplus
}
#endif

#endif /*SET_H*/