/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc filetable document

	@module	filetable.h | interface file

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

#ifndef _FILETABLE_H
#define _FILETABLE_H

#include "../xdkdef.h"

#define FILETABLE_PRIVATE	0x00
#define FILETABLE_SHARE		0x01

#define BLOCK_SIZE_64		64
#define BLOCK_SIZE_128		128
#define BLOCK_SIZE_256		256
#define BLOCK_SIZE_512		512

#define INVALID_BLOCK	((dword_t)(-1))
#define INVALID_INDEX	((lword_t)(-1))

#ifdef	__cplusplus
extern "C" {
#endif


/***********************************************************************
@FUNCTION: create file table.
@INPUT: the file name of file table.
@INPUT: the block size of file table, can be BLOCK_SIZE_512, BLOCK_SIZE_1024,
	BLOCK_SIZE_2048, BLOCK_SIZE_4096.
@INPUT: the mask of file table, can be FILETABLE_SHARE, FILETABLE_PRIVATE.
	the file table careate with FILETABLE_PRIVATE indicate none-lock mode, 
	or FILETABLE_SHARE with spin-lock mode.
@RETURN: the link component of file table or NULL if failed.
@NOTE: if disk file exists, file table load it, otherwise create a new disk file
	with initialized file table content.
***********************************************************************/
EXP_API link_t_ptr create_file_table(const tchar_t* fname, int block, dword_t mask);

/***********************************************************************
@FUNCTION: destroy a file table.
@INPUT: the file table link component.
@RETURN: none.
***********************************************************************/
EXP_API void destroy_file_table(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: get the file table page size.
@INPUT: the file table link component.
@RETURN: return the page size.
***********************************************************************/
EXP_API int get_file_table_page_size(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: get the file table block's size.
@INPUT: the file table link component.
@RETURN: return the block size.
***********************************************************************/
EXP_API int get_file_table_block_size(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: get the file table mask.
@INPUT: the file table link component.
@RETURN: return the mask.
***********************************************************************/
EXP_API dword_t get_file_table_mask(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: set the file table root block index.
@INPUT: the file table link component.
@INPUT: the zero based block index.
@RETURN: return nonzero for succeed, return zero if failed.
***********************************************************************/
EXP_API bool_t set_file_table_root(link_t_ptr ptr, lword_t bid);

/***********************************************************************
@FUNCTION: get the file table root block index.
@INPUT: the file table link component.
@RETURN: return the root block index.
***********************************************************************/
EXP_API lword_t get_file_table_root(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: alloc a file block.
@INPUT: the file table link component.
@INPUT: the size needed.
@RETURN: if succeeds return the block index, failed return INVALID_SIZE.
***********************************************************************/
EXP_API lword_t alloc_file_table_block(link_t_ptr ptr, dword_t size);

/***********************************************************************
@FUNCTION: free a file block.
@INPUT: the file table link component.
@INPUT: the file block index.
@INPUT: the size of file block.
@RETURN: none.
@NOTE: the size must be same as original size when alloc_file_table_block called.
***********************************************************************/
EXP_API void free_file_table_block(link_t_ptr ptr, lword_t bid, dword_t size);

/***********************************************************************
@FUNCTION: test a file block is alloced at the position.
@INPUT: the file table link component.
@INPUT: the file block index.
@RETURN: return nonzero for alloced, otherwise return zero.
***********************************************************************/
EXP_API bool_t get_file_table_block_alloced(link_t_ptr ptr, lword_t bid);

/***********************************************************************
@FUNCTION: lock a file block for read/write
@INPUT: the file table link component.
@INPUT: the file block index.
@INPUT: the need bytes.
@INPUT: none zero indicate the block for writing, zero for reading.
@OUTPUT: if succeed the file mapping handle returned.
@RETURN: if succeeds the block address returned, fails return NULL.
***********************************************************************/
EXP_API void* lock_file_table_block(link_t_ptr ptr, lword_t bid, dword_t size, bool_t write, res_file_t* pmh);

/***********************************************************************
@FUNCTION: unlock a file block for ending read or write
@INPUT: the file table link component.
@INPUT: the file block index.
@INPUT: the need bytes.
@INPUT: none zero indicate the block for writing, zero for reading.
@INPUT: the file mapping handle.
@INPUT: the block address.
@RETURN: none.
@NOTE: the file mapping handle also be released.
***********************************************************************/
EXP_API void unlock_file_table_block(link_t_ptr ptr, lword_t bid, dword_t size, bool_t write, res_file_t mh, void* buf);

/***********************************************************************
@FUNCTION: free unalloced block and truncate file size
@INPUT: the file table link component.
@RETURN: none.
***********************************************************************/
EXP_API void trunc_file_table(link_t_ptr ptr);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void file_table_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_FILETABLE_H*/