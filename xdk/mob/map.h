/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc map document

	@module	map.h | interface file

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

#ifndef _MAP_H
#define _MAP_H

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************************************
@FUNCTION: calc map bytes needed.
@INPUT: count of number.
@INPUT: the flag bits.
@RETURN: the bytes.
***********************************************************************/
EXP_API dword_t map_need_size(dword_t nums, int bits);

/**********************************************************************
@FUNCTION: alloc a map.
@INPUT: count of number.
@INPUT: the flag bits.
@RETURN: map object.
@NOTE: the inner data buffer not alloced, must attach later.
***********************************************************************/
EXP_API map_t map_alloc(dword_t nums, int bits);

/**********************************************************************
@FUNCTION: free a map.
@INPUT: the map object.
@RETURN: none.
@NOTE: the inner data buffer must detach firster.
***********************************************************************/
EXP_API void map_free(map_t map);

/**********************************************************************
@FUNCTION: get map data buffer for read only.
@INPUT: the map object.
@RETURN: the data buffer.
***********************************************************************/
EXP_API const void* map_data(map_t map);

/**********************************************************************
@FUNCTION: attach data buffer to map.
@INPUT: the map object.
@INPUT: the data buffer.
@RETURN: none.
@NOTE: the buffer can be memory block for slight map operating,
	or virtual disk space mapped address for large map.
***********************************************************************/
EXP_API void map_attach(map_t map, void* data);

/**********************************************************************
@FUNCTION: detach map data buffer.
@INPUT: the map object.
@RETURN: the buffer address.
***********************************************************************/
EXP_API void* map_detach(map_t map);

/**********************************************************************
@FUNCTION: copy the map.
@INPUT: the destination map object.
@INPUT: the srource map object.
@RETURN: none.
@NOTE: the destination map's number and bits must equal to source map,
	and data buffer must be attached.
***********************************************************************/
EXP_API void map_copy(map_t dst, map_t src);

/**********************************************************************
@FUNCTION: set flag to zero in map.
@INPUT: the map object.
@RETURN: none.
***********************************************************************/
EXP_API void map_zero(map_t map);

/**********************************************************************
@FUNCTION: get map data bytes attached.
@INPUT: the map object.
@RETURN: size in bytes if data attached, otherwise return zero.
***********************************************************************/
EXP_API dword_t map_size(map_t map);

/**********************************************************************
@FUNCTION: get map bits.
@INPUT: the map object.
@RETURN: bits.
***********************************************************************/
EXP_API int map_bits(map_t map);

/**********************************************************************
@FUNCTION: set map item flag.
@INPUT: the map object.
@INPUT: the index of item.
@INPUT: the flag bit.
@RETURN: none.
***********************************************************************/
EXP_API void map_set_bit(map_t map, dword_t i, byte_t tag);

/**********************************************************************
@FUNCTION: get map item flag.
@INPUT: the map object.
@INPUT: the index of item.
@RETURN: return the flag bit.
***********************************************************************/
EXP_API byte_t map_get_bit(map_t map, dword_t i);

/**********************************************************************
@FUNCTION: find the flaged item begin at the position in map.
@INPUT: the map object.
@INPUT: the start position.
@INPUT: the tag bit to seek.
@RETURN: return the index if exists, otherwise return INVALID_BLOCK.
***********************************************************************/
EXP_API dword_t map_find_bit(map_t map, dword_t i, byte_t tag);

/**********************************************************************
@FUNCTION: test the sequent items with tag in map.
@INPUT: the map object.
@INPUT: the start position.
@INPUT: the flag bit.
@INPUT: the seek step.
@RETURN: item count with the same tag, otherwise return INVALID_BLOCK.
***********************************************************************/
EXP_API dword_t map_test_bit(map_t map, dword_t i, byte_t tag, dword_t n);

/**********************************************************************
@FUNCTION: parse map element from string.
@INPUT: the map object.
@INPUT: string token, items separated by space.
@INPUT: string token characters.
@RETURN: none.
***********************************************************************/
EXP_API void map_parse(map_t map, const tchar_t* str, int len);

/**********************************************************************
@FUNCTION: formap map element to string.
@INPUT: the map object.
@OUTPUT: buffer for formaping.
@INPUT: the buffer size in characters, not include terminate character.
@RETURN: the formated characters in buffer.
***********************************************************************/
EXP_API int map_format(map_t map, tchar_t* buf, int max);

/**********************************************************************
@FUNCTION: encode map object to bytes buffer.
@INPUT: the map object.
@OUTPUT: the bytes buffer.
@INPUT: the buffer size in bytes.
@RETURN: encoded bytes, zero for failed.
@NOTE: buffer can be NULL for testing how many bytes will be encoded.
***********************************************************************/
EXP_API dword_t map_encode(map_t map, byte_t* buf);

/**********************************************************************
@FUNCTION: decode map object from bytes buffer.
@INPUT: the map object.
@INPUT: the data buffer.
@RETURN: bytes decoded, zero for failed.
@NOTE: map can be NULL for testing how many bytes will be decoded.
***********************************************************************/
EXP_API dword_t map_decode(map_t map, const byte_t* buf);


#if defined (DEBUG) || defined (_DEBUG)
EXP_API void map_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_MAP_H*/