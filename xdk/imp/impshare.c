﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc block document

	@module	impshare.c | implement file

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

#include "impshare.h"

#include "../xdkimp.h"
#include "../xdkstd.h"

#ifdef XDK_SUPPORT_SHARE

typedef struct _share_context{
	handle_head head;

	res_file_t block;
    
	dword_t write_bytes;
	dword_t read_bytes;

    bool_t b_srv;
	tchar_t* sname;
}share_context;

xhand_t xshare_srv(const tchar_t* pname, const tchar_t* fpath, dword_t hoff, dword_t loff, dword_t size)
{
	share_context* ppi;
	if_share_t* pif;
	res_file_t bh;

	pif = PROCESS_SHARE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	bh = (*pif->pf_share_srv)(pname, fpath, hoff, loff, size);

	if (bh == INVALID_FILE)
	{
		set_system_error(_T("pf_share_open"));
		return NULL;
	}

	ppi = (share_context*)xmem_alloc(sizeof(share_context));
	ppi->head.tag = _HANDLE_SHARE;
	ppi->block = bh;
	ppi->write_bytes = 0;
	ppi->read_bytes = 0;
    ppi->b_srv = 1;
	ppi->sname = xsclone(pname);

	return &ppi->head;
}

xhand_t xshare_cli(const tchar_t* pname, dword_t size, dword_t fmode)
{
	share_context* ppi;
	if_share_t* pif;
	res_file_t bh;

	pif = PROCESS_SHARE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	bh = (*pif->pf_share_cli)(pname, size, fmode);

	if (bh == INVALID_FILE)
	{
		set_system_error(_T("pf_share_open"));
		return NULL;
	}

	ppi = (share_context*)xmem_alloc(sizeof(share_context));
	ppi->head.tag = _HANDLE_SHARE;
	ppi->block = bh;
	ppi->write_bytes = 0;
	ppi->read_bytes = 0;
    ppi->b_srv = 0;
	ppi->sname = xsclone(pname);

	return &ppi->head;
}

res_file_t xshare_handle(xhand_t block)
{
	share_context* ppi = TypePtrFromHead(share_context, block);

	XDK_ASSERT(block && block->tag == _HANDLE_SHARE);

	return ppi->block;
}

void xshare_close(xhand_t block)
{
	share_context* ppi = TypePtrFromHead(share_context, block);
	if_share_t* pif;

	XDK_ASSERT(block && block->tag == _HANDLE_SHARE);

	pif = PROCESS_SHARE_INTERFACE;

	XDK_ASSERT(pif != NULL);

    if(ppi->b_srv)
        (*pif->pf_share_close)(ppi->sname, ppi->block);
    else
        (*pif->pf_share_close)(NULL, ppi->block);

	xsfree(ppi->sname);

	xmem_free(ppi);
}

bool_t xshare_read(xhand_t block, byte_t* buf, dword_t* pcb)
{
	share_context* ppt = TypePtrFromHead(share_context, block);
	if_share_t* pif;
	dword_t size;

	XDK_ASSERT(block && block->tag == _HANDLE_SHARE);

	pif = PROCESS_SHARE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	size = *pcb;
	if(!(*pif->pf_share_read)(ppt->block, ppt->read_bytes, buf, size, &size))
	{
		set_system_error(_T("pf_share_read"));
		*pcb = 0;
		return 0;
	}
	
	ppt->read_bytes += size;

	*pcb = size;
	return 1;
}

bool_t xshare_write(xhand_t block, const byte_t* buf, dword_t* pcb)
{
	share_context* ppt = TypePtrFromHead(share_context, block);
	if_share_t* pif;
	dword_t size;

	XDK_ASSERT(block && block->tag == _HANDLE_SHARE);

	pif = PROCESS_SHARE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	size = *pcb;
	if(!(*pif->pf_share_write)(ppt->block, ppt->write_bytes, (void*)buf, size, &size))
	{
		set_system_error(_T("pf_share_write"));
		*pcb = 0;
		return 0;
	}

	ppt->write_bytes += size;

	*pcb = size;
	return 1;
}

void* xshare_lock(xhand_t block, dword_t offset, dword_t size)
{
	share_context* ppt = TypePtrFromHead(share_context, block);
	if_share_t* pif;

	XDK_ASSERT(block && block->tag == _HANDLE_SHARE);

	pif = PROCESS_SHARE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_share_lock)(ppt->block, offset, size);
}

void xshare_unlock(xhand_t block, dword_t offset, dword_t size, void* p)
{
	share_context* ppt = TypePtrFromHead(share_context, block);
	if_share_t* pif;

	XDK_ASSERT(block && block->tag == _HANDLE_SHARE);

	pif = PROCESS_SHARE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	(*pif->pf_share_unlock)(ppt->block, offset, size, p);
}

#endif //XDK_SUPPORT_SHARE
