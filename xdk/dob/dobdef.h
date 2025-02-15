/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc dob defination document

	@module	xdkdef.h | interface file

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


#ifndef _DOBDEF_H
#define	_DOBDEF_H

typedef struct _link_t* link_t_ptr;
typedef struct _link_t{
	byte_t tag;
	byte_t lru[3];
	link_t_ptr prev;	/*previous component link*/
	link_t_ptr next;	/*next component link*/
}link_t;


/*define root link tag*/
#define lkRoot			0xFF
/*define free link tag*/
#define lkFree			0x00

#define lkDebug			0xFE

#define lkDoc			0x01
#define lkNode			0x02

#define lkHashTable		0x03
#define lkHashEntity	0x04

#define lkListTable		0x05
#define lkListNode		0x06

#define lkStringTable	0x07
#define lkStringEntity	0x08

#define lkDictTable		0x09
#define lkDictEntity	0x0A

#define lkWordsTable	0x0B
#define lkWordsItem		0x0C

#define lkTrieNode		0x0D
#define lkTrieLeaf		0x0E

#define lkStackTable	0x0F

#define lkBinaTree		0x10
#define lkBinaNode		0x11

#define lkBplusTree		0x12
#define lkBplusIndex	0x13
#define lkBplusData		0x14

#define lkACTable		0x15

#define lkMultiTree		0x16

#define lkFileTable		0x17
#define lkLockTable		0x18

#define IS_DOM_DOC(ptr)		((ptr->tag == lkNode)? 1 : 0)
#define IS_XML_DOC(ptr)		((ptr->tag == lkDoc)? 1 : 0)

#ifdef _OS_64
#define LINK_FIRST	((link_t_ptr)((unsigned long long)1))		
#define LINK_LAST	((link_t_ptr)((unsigned long long)-1))
#else
#define LINK_FIRST	((link_t_ptr)((unsigned int)1))		
#define LINK_LAST	((link_t_ptr)((unsigned int)-1))
#endif


#ifdef _OS_64
#define TypePtrFromHead(type,p) ((type*)((unsigned long long)p - (unsigned long long)&(((type*)0)->head))) 
#else
#define TypePtrFromHead(type,p) ((type*)((unsigned int)p - (unsigned int)&(((type*)0)->head))) 
#endif


#ifdef _OS_64
#define TypePtrFromLink(type,p) ((type*)((unsigned long long)p - (unsigned long long)&(((type*)0)->lk))) 
#define TypePtrFromChild(type,p) ((type*)((unsigned long long)p - (unsigned long long)&(((type*)0)->lkChild))) 
#define TypePtrFromSibling(type,p) ((type*)((unsigned long long)p - (unsigned long long)&(((type*)0)->lkSibling))) 
#else
#define TypePtrFromLink(type,p) ((type*)((unsigned int)p - (unsigned int)&(((type*)0)->lk))) 
#define TypePtrFromChild(type,p) ((type*)((unsigned int)p - (unsigned int)&(((type*)0)->lkChild))) 
#define TypePtrFromSibling(type,p) ((type*)((unsigned int)p - (unsigned int)&(((type*)0)->lkSibling))) 
#endif

typedef enum{
	ORDER_NONE = 0,
	ORDER_ASCEND = 1,
	ORDER_DESCEND = -1
}SORT_ORDER;

/*sort link node callback function*/
typedef int(*CALLBACK_SORTLINK)(link_t_ptr plk1, link_t_ptr plk2, void* pv);

/*enum link node callback function*/
typedef bool_t(*CALLBACK_ENUMLINK)(link_t_ptr plk, void* pv);



#endif	/* _DOBDEF_H */

