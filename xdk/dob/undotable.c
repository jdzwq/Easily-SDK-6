/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc undotable document

	@module	undotable.c | implement file

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

#include "undotable.h"

#include "../xdkstd.h"
#include "../xdkobj.h"
#include "../xdkimp.h"

#define IS_UNDO_BOM(buf) ((buf[0] == 'U' && buf[1] == 'N' && buf[2] == 'D' && buf[3] == 'O')? 1 : 0)

typedef struct _undo_table_context{
	link_t lk;

	xhand_t file;
	dword_t blocks;

	dword_t offset;
	dword_t bytes;
}undo_table_context;

#define UndoTableFromLink(p) TypePtrFromLink(undo_table_context,p)

/************************************************************************************/

link_t_ptr create_undo_table(const tchar_t* fname)
{
	undo_table_context* ppt = NULL;

	lword_t ll = 0;
	dword_t n;
	byte_t buf[4] = {'U','N','D','O'};

	TRY_CATCH;

	ppt = (undo_table_context*)xmem_alloc(sizeof(undo_table_context));
	ppt->lk.tag = lkUndoTable;

	ppt->file = xuncf_open_file(NULL, fname, FILE_OPEN_APPEND | FILE_OPEN_RANDOM);
	if (!ppt->file)
	{
		raise_user_error(NULL, NULL);
	}

	xuncf_file_size(ppt->file, &ll);

	if (ll)
	{	
		n = 4;
		if(!xuncf_read_file(ppt->file, buf, &n))
		{
			raise_user_error(_T("create_undo_table"), _T("no undo table head"));
		}
		if(!IS_UNDO_BOM(buf))
		{
			raise_user_error(_T("create_undo_table"), _T("not undo table file"));
		}

		n = 4;
		if(!xuncf_read_file(ppt->file, buf, &n))
		{
			raise_user_error(_T("create_undo_table"), _T("no undo table count"));
		}
		ppt->blocks = GET_DWORD_NET(buf, 0);
	}
	else
	{
		n = 4;
		if(!xuncf_write_file(ppt->file, buf, &n))
		{
			raise_user_error(_T("create_undo_table"), _T("write undo table head"));
		}

		ppt->blocks = 0;
		PUT_DWORD_NET(buf, 0, ppt->blocks);

		n = 4;
		if(!xuncf_write_file(ppt->file, buf, &n))
		{
			raise_user_error(_T("create_undo_table"), _T("write undo table count"));
		}
	}

	END_CATCH;

	return &ppt->lk;
ONERROR:

	if (ppt->file)
		xuncf_close_file(ppt->file);

	if (ppt)
		xmem_free(ppt);

	return NULL;
}

void destroy_undo_table(link_t_ptr ptr)
{
	undo_table_context* ppt = UndoTableFromLink(ptr);
	int i;

	XDK_ASSERT(ptr && ptr->tag == lkUndoTable);

	xuncf_close_file(ppt->file);

	xmem_free(ppt);
}

dword_t get_undo_table_blocks(link_t_ptr ptr)
{
	undo_table_context* ppt = UndoTableFromLink(ptr);

	return ppt->blocks;
}
