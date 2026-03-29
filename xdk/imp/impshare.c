/***********************************************************************
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

#include "../xdkstd.h"
#include "../xdkimp.h"

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

	ppi = (share_context*)xmem_alloc_handle(sizeof(share_context));
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

	ppi = (share_context*)xmem_alloc_handle(sizeof(share_context));
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

	xmem_free_handle((xhand_t)ppi);
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

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void xshare_test_cli()
{
	xhand_t ch = NULL;
	unsigned char buf[4096] = {0};
    dword_t dw = 0;

	TRY_CATCH;

    ch = xshare_cli(_T("mytest"),MAX_LONG, FILE_OPEN_CREATE);
    if(!ch)
    {
		raise_user_error(_T("test_share_cli"),_T("xshare_cli"));
	}

    a_xscpy((schar_t*)buf, "hello word!");
	dw = 4096;
    if(!xshare_write(ch, buf, &dw))
	{
		raise_user_error(_T("test_share_cli"),_T("xshare_write"));
	}

    xmem_zero((void*)buf, 4096);
    dw = 4096;
    if(!xshare_read(ch, buf, &dw))
    {
		raise_user_error(_T("test_share_cli"),_T("xshare_write"));
	}
    
    xshare_close(ch);
	ch = NULL;

	END_CATCH;

	return;
ONERROR:
	XDK_TRACE_LAST;

	if(ch) xshare_close(ch);

	return;
}

#ifndef _OS_WINDOWS
void xshare_test_srv()
{
    if_share_t* pif_share = PROCESS_SHARE_INTERFACE;
    
	tchar_t fname[1024];
	get_runpath(0, fname, 1024);
	xscat(fname,_T("/demo.txt"));

    res_file_t fh = (*pif_share->pf_share_srv)(_T("mytest"),fname,0,0,1024);
    if(fh == INVALID_FILE)
	{
        printf("parent error : %s\n", strerror(errno));
		return;
	}else{
		printf("parent share server: %s\n", "mytest");
	}
    
    char buf[4096] = {0};
    dword_t dw = 0;
    
    pid_t pid;
    int status;
    
    pid = fork();
    //kill(0, SIGSTOP);
    
    if(pid == 0)
    {
		res_file_t ch = (*pif_share->pf_share_cli)(_T("mytest"), 1024, FILE_OPEN_READ);

		if (ch == INVALID_FILE)
		{
			printf("child error : %s\n", strerror(errno));
			exit(-1);
		}else
		{
			memset((void *)buf, 0, 4096);
			dw = 0;
			if (!(*pif_share->pf_share_read)(ch, 0, buf, 4096, &dw))
				printf("child error : %s\n", strerror(errno));
			else
				printf("child read mytest: %s\n", buf);

			(*pif_share->pf_share_close)(_T("mytest"), ch);
			exit(0);
		}
	}
    else
	{
        waitpid(pid, &status, 0);
		printf("Child exited with status: %d\n", WEXITSTATUS(status));

        (*pif_share->pf_share_close)(_T("mytest"), fh);
    }
}
#endif //_OS_WINDOWS
#endif 

#endif //XDK_SUPPORT_SHARE
