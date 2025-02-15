/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc object handle defination document

	@module	objdef.h | interface file

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


#ifndef _MOBDEF_H
#define	_MOBDEF_H


typedef struct _memobj_head{
	byte_t tag; //memo object type
	byte_t len[3]; //memo object size in bytes
}memobj_head;

#define MEMOBJ_SIZE(obj)		(GET_THREEBYTE_LOC(((obj)->len), 0) + sizeof(memobj_head))

#define MEM_BINARY	0x00
#define MEM_VARIANT	0x01
#define MEM_STRING	0x02
#define MEM_MAP		0x03
#define MEM_VECTOR	0x04
#define MEM_MATRIX	0x04 //equal to vector
#define MEM_SET		0x05
#define MEM_DOMDOC	0x0A
#define MEM_MESSAGE	0x0B
#define MEM_QUEUE	0x0C
#define MEM_LINEAR	0x0D
#define MEM_SPINLOCK	0x0E

#define MEMENC_MASK	0x10

#define IS_OBJECT_TYPE(tag)		((tag >= 0x10 && tag <= 0x1F)? 1 : 0)

typedef struct _memobj_head **object_t;
typedef struct _memobj_head **message_t;
typedef struct _memobj_head **queue_t;
typedef struct _memobj_head *variant_t;
typedef struct _memobj_head *string_t;
typedef struct _memobj_head *map_t;
typedef struct _memobj_head *vector_t;
typedef struct _memobj_head *matrix_t;
typedef struct _memobj_head *linear_t;
typedef struct _memobj_head *spinlock_t;


#endif	/* _OBJDEF_H */

