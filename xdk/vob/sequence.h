/***********************************************************************
	Easily SDK 6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc sequence buffer document

	@module	sequence.h | interface file

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

#ifndef _SEQUENCE_H
#define _SEQUENCE_H

#include "../xdkdef.h"


#ifdef	__cplusplus
extern "C" {
#endif

	EXP_API sequence_t alloc_sequence(int wins);

	EXP_API void clear_sequence(sequence_t lin);

	EXP_API void free_sequence(sequence_t lin);

	EXP_API byte_t* insert_sequence_frame(sequence_t lin, int seqnum, dword_t frmlen);

	EXP_API bool_t delete_sequence_frame(sequence_t lin, int seqnum);

	EXP_API void clean_sequence_frame(sequence_t lin, int seqnum);

	EXP_API byte_t* get_sequence_frame(sequence_t lin, int seqnum, dword_t* pb);

	EXP_API int get_sequence_window(sequence_t lin);

	EXP_API int get_sequence_top(sequence_t lin);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void sequence_self_test();
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_SEQUENCE_H*/
