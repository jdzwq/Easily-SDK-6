﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc pipe document

	@module	imppipe.c | implement file

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

#include "imppipe.h"

#include "../xdkimp.h"
#include "../xdkstd.h"

#ifdef XDK_SUPPORT_PIPE

typedef struct _pipe_context{
	handle_head head;

	res_file_t pipe;
	bool_t b_srv;
	tchar_t* pname;

	async_t* pov;
}pipe_context;

xhand_t xpipe_srv(const tchar_t* pname, dword_t fmode)
{
	res_file_t pd;
	pipe_context* ppi;
	if_pipe_t* pif;

	pif = PROCESS_PIPE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	pd = (*pif->pf_pipe_srv)(pname, fmode);

	if (pd == INVALID_FILE)
	{
		set_system_error(_T("pf_pipe_srv"));
		return NULL;
	}

	ppi = (pipe_context*)xmem_alloc(sizeof(pipe_context));
	ppi->head.tag = _HANDLE_PIPE;
	ppi->pipe = pd;
	ppi->b_srv = 1;
	ppi->pname = xsclone(pname);

	ppi->pov = (async_t*)xmem_alloc(sizeof(async_t));
	async_init(ppi->pov, ((fmode & FILE_OPEN_OVERLAP) ? ASYNC_EVENT : ASYNC_BLOCK), PIPE_BASE_TIMO, INVALID_FILE);

	return &ppi->head;
}

bool_t xpipe_listen(xhand_t pip)
{
	pipe_context* ppi = TypePtrFromHead(pipe_context, pip);
	if_pipe_t* pif;
    bool_t rt;

	XDK_ASSERT(pip && pip->tag == _HANDLE_PIPE);

	pif = PROCESS_PIPE_INTERFACE;

	XDK_ASSERT(pif != NULL);

    rt = (*pif->pf_pipe_listen)(ppi->pipe, ppi->pov);
    
    return rt;
}

void xpipe_stop(xhand_t pip)
{
	pipe_context* ppi = TypePtrFromHead(pipe_context, pip);
	if_pipe_t* pif;

	XDK_ASSERT(pip && pip->tag == _HANDLE_PIPE);

	pif = PROCESS_PIPE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	(*pif->pf_pipe_stop)(ppi->pipe);
}

xhand_t xpipe_cli(const tchar_t* pname, dword_t fmode)
{
	res_file_t pd;
	pipe_context* ppi;
	if_pipe_t* pif;

	pif = PROCESS_PIPE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	pd = (*pif->pf_pipe_cli)(pname, fmode);

	if (pd == INVALID_FILE)
	{
		set_system_error(_T("pf_pipe_cli"));
		return NULL;
	}

	ppi = (pipe_context*)xmem_alloc(sizeof(pipe_context));
	ppi->head.tag = _HANDLE_PIPE;
	ppi->pipe = pd;
	ppi->b_srv = 0;
	ppi->pname = xsclone(pname);

	ppi->pov = (async_t*)xmem_alloc(sizeof(async_t));
	async_init(ppi->pov, ((fmode & FILE_OPEN_OVERLAP) ? ASYNC_EVENT : ASYNC_BLOCK), PIPE_BASE_TIMO, INVALID_FILE);

	return &ppi->head;
}

xhand_t xpipe_attach(res_file_t hp)
{
	pipe_context* ppi;
	if_pipe_t* pif;

	pif = PROCESS_PIPE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	ppi = (pipe_context*)xmem_alloc(sizeof(pipe_context));
	ppi->head.tag = _HANDLE_PIPE;
	ppi->pipe = hp;

	ppi->pov = (async_t*)xmem_alloc(sizeof(async_t));
	async_init(ppi->pov, ASYNC_BLOCK, PIPE_BASE_TIMO, INVALID_FILE);

	return &ppi->head;
}

res_file_t xpipe_detach(xhand_t pip)
{
	pipe_context* ppi = TypePtrFromHead(pipe_context, pip);
	res_file_t hp;

	XDK_ASSERT(pip && pip->tag == _HANDLE_PIPE);

	hp = ppi->pipe;

	if (ppi->pov)
	{
		async_uninit(ppi->pov);
		xmem_free(ppi->pov);
	}

	xmem_free(ppi);

	return hp;
}

res_file_t xpipe_handle(xhand_t pip)
{
	pipe_context* ppi = TypePtrFromHead(pipe_context, pip);

	XDK_ASSERT(pip && pip->tag == _HANDLE_PIPE);

	return ppi->pipe;
}

wait_t xpipe_wait(const tchar_t* pname, int ms)
{
	if_pipe_t* pif;

	pif = PROCESS_PIPE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_pipe_wait)(pname, ms);
}

bool_t xpipe_flush(xhand_t pip)
{
	pipe_context* ppi = TypePtrFromHead(pipe_context, pip);
	if_pipe_t* pif;

	XDK_ASSERT(pip && pip->tag == _HANDLE_PIPE);

	pif = PROCESS_PIPE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	if (ppi->pipe)
		return (*pif->pf_pipe_flush)(ppi->pipe);
	else
		return 0;
}

void xpipe_free(xhand_t pip)
{
	pipe_context* ppi = TypePtrFromHead(pipe_context, pip);
	if_pipe_t* pif;

	XDK_ASSERT(pip && pip->tag == _HANDLE_PIPE);

	pif = PROCESS_PIPE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	if (ppi->b_srv && ppi->pipe)
	{
		(*pif->pf_pipe_stop)(ppi->pipe);
	}
	
	if (ppi->pipe)
	{
        if(ppi->b_srv)
            (*pif->pf_pipe_close)(ppi->pname, ppi->pipe);
        else
            (*pif->pf_pipe_close)(NULL, ppi->pipe);
	}

	if (ppi->pov)
	{
		async_uninit(ppi->pov);
		xmem_free(ppi->pov);
	}

	xsfree(ppi->pname);
	xmem_free(ppi);
}

bool_t xpipe_write(xhand_t pip, const byte_t* buf, dword_t* pcb)
{
	pipe_context* ppt = (pipe_context*)pip;
	if_pipe_t* pif;
	dword_t size, pos = 0;

	XDK_ASSERT(pip && pip->tag == _HANDLE_PIPE);

	pif = PROCESS_PIPE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	size = *pcb;

	while (pos < size)
	{
		ppt->pov->size = 0;
		if (!(*pif->pf_pipe_write)(ppt->pipe, (void*)(buf + pos), size - pos, ppt->pov))
		{
			set_system_error(_T("pf_pipe_write"));

			*pcb = (dword_t)pos;

			return 0;
		}

		if (!(ppt->pov->size)) break;

		pos += (ppt->pov->size);
	}

	*pcb = (dword_t)pos;

	return 1;
}

bool_t xpipe_read(xhand_t pip, byte_t* buf, dword_t* pcb)
{
	pipe_context* ppt = (pipe_context*)pip;
	if_pipe_t* pif;
	dword_t size, pos = 0;

	XDK_ASSERT(pip && pip->tag == _HANDLE_PIPE);

	pif = PROCESS_PIPE_INTERFACE;

	XDK_ASSERT(pif != NULL);

	size = *pcb;

	while (pos < size)
	{
		ppt->pov->size = 0;
		if (!(*pif->pf_pipe_read)(ppt->pipe, (void*)(buf + pos), size - pos, ppt->pov))
		{
			set_system_error(_T("pf_pipe_read"));

			*pcb = pos;

			return 0;
		}

		if (!(ppt->pov->size)) break;

		pos += (ppt->pov->size);
	}

	*pcb = pos;

	return 1;
}

#endif //XDK_SUPPORT_PIPE
