/***********************************************************************
	Easily SDK 6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc array object document

	@module	wordarray.h | interface file

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

#ifndef _WORDARRAY_H
#define _WORDARRAY_H

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

/***********************************************************************
@FUNCTION: alloc a words array.
@RETURN: the words array object.
***********************************************************************/
EXP_API sword_t** words_alloc(void);

/***********************************************************************
@FUNCTION: realloc the words array due to array size changed.
@INPUT: the original words array object.
@INPUT: the number of words needed.
@RETURN: the words array inner buffer.
***********************************************************************/
EXP_API sword_t* words_realloc(sword_t** pp, int count);

/***********************************************************************
@FUNCTION: free the words array.
@INPUT: the words array object.
@RETURN: none.
***********************************************************************/
EXP_API void words_free(sword_t** sa);

/***********************************************************************
@FUNCTION: clear the words array content.
@INPUT: the words array object.
@RETURN: none.
***********************************************************************/
EXP_API void words_clear(sword_t** sa);

/***********************************************************************
@FUNCTION: get the words array size.
@INPUT: the words array object.
@RETURN: the number of words in array.
***********************************************************************/
EXP_API int words_size(sword_t** sa);

/***********************************************************************
@FUNCTION: get the words item by index.
@INPUT: the words array object.
@INPUT: the zero-based position.
@RETURN: the words item at a valid index.
***********************************************************************/
EXP_API sword_t get_words(sword_t** sa, int index);

/***********************************************************************
@FUNCTION: get the words item safed.
@INPUT: the words array object.
@INPUT: the zero-based position.
@INPUT: the default value.
@RETURN: the words item at a valid index or the default value.
@NOTE: if index is invalid then default value returned.
***********************************************************************/
EXP_API sword_t get_words_safe(sword_t** sa, int index, sword_t def);

/***********************************************************************
@FUNCTION: copy some words into words array object.
@INPUT: the words array object.
@INPUT: the zero-based position.
@INPUT: the words array buffer.
@INPUT: the numner of words array.
@RETURN: the number of words copyed.
@NOTE: the max words item can be copy into is (object size - index).
***********************************************************************/
EXP_API int words_copy(sword_t** sa, int index, sword_t* buf, int max);

/***********************************************************************
@FUNCTION: insert some words into words array object.
@INPUT: the words array object.
@INPUT: the zero-based position.
@INPUT: the words array buffer.
@INPUT: the numner of words array.
@RETURN: none.
@NOTE: the new words array object size is (original size + count),
	the words array may be expended.
***********************************************************************/
EXP_API void words_insert(sword_t** sa, int index, const sword_t* pa, int count);

/***********************************************************************
@FUNCTION: delete some words from words array object.
@INPUT: the words array object.
@INPUT: the zero-based position.
@INPUT: the numner of words will to delete.
@RETURN: none.
@NOTE: the max words item can be deleted is (object size - index),
	the words array may be truncted.
***********************************************************************/
EXP_API void words_delete(sword_t** sa, int index, int count);

/***********************************************************************
@FUNCTION: attach a words buffer to the words array object.
@INPUT: the words array object.
@INPUT: the words buffer.
@INPUT: the numner of words items.
@RETURN: none.
@NOTE: the words buffer of words array object is alloced outside,
	it must be detached and freed outside.
***********************************************************************/
EXP_API void words_attach(sword_t** pp, sword_t* p, int len);

/***********************************************************************
@FUNCTION: detach words buffer from words array object.
@INPUT: the words array object.
@RETURN: the words buffer.
***********************************************************************/
EXP_API sword_t* words_detach(sword_t** pp);



#ifdef	__cplusplus
}
#endif

#endif //_WORDARRAY_H
