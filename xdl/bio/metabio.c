﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc document utility

	@module	docmeta.c | implement file

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

#include "metabio.h"

#include "../xdlutil.h"
#include "../xdlbio.h"
#include "../xdldoc.h"


bool_t save_xml_doc_to_file(link_t_ptr xml, const secu_desc_t* psd, const tchar_t* fname)
{
	file_t xf = NULL;
	byte_t* buf = NULL;
	dword_t size;

	TRY_CATCH;

	xf = xfile_open(psd, fname, FILE_OPEN_CREATE);
	if (!xf)
	{
		raise_user_error(NULL, NULL);
	}

	size = format_xml_doc_to_bytes(xml, NULL, MAX_LONG);

	buf = (byte_t*)xmem_alloc(size);

	format_xml_doc_to_bytes(xml, buf, size);

	if (!xfile_write(xf, buf, size))
	{
		raise_user_error(NULL, NULL);
	}
	
	xmem_free(buf);
	buf = NULL;

	xfile_close(xf);
	xf = NULL;

	END_CATCH;

	return 1;
ONERROR:

	if (buf)
		xmem_free(buf);

	if (xf)
		xfile_close(xf);

#if defined(_DEBUG) || defined(DEBUG)
	XDK_TRACE_LAST;
#endif

	return 0;
}

bool_t load_xml_doc_from_file(link_t_ptr xml, const secu_desc_t* psd, const tchar_t* fname)
{
	file_t xf = NULL;
	byte_t* buf = NULL;

	tchar_t fsize[INT_LEN + 1] = { 0 };
	dword_t size;

	TRY_CATCH;

	if (!xfile_info(psd, fname, NULL, fsize, NULL, NULL))
	{
		raise_user_error(NULL, NULL);
	}

	if (is_huge_size(fsize))
	{
		raise_user_error(_T("0"), _T("not support huge size file"));
	}

	xf = xfile_open(psd, fname, FILE_OPEN_READ);
	if (!xf)
	{
		raise_user_error(NULL, NULL);
	}

	size = xstol(fsize);
	buf = (byte_t*)xmem_alloc(size);

	if (!xfile_read(xf, buf, size))
	{
		raise_user_error(NULL, NULL);
	}

	if (!parse_xml_doc_from_bytes(xml, buf, size))
	{
		raise_user_error(NULL, NULL);
	}

	xmem_free(buf);
	buf = NULL;
	
	xfile_close(xf);
	xf = NULL;

	END_CATCH;

	return 1;
ONERROR:

	if (buf)
		xmem_free(buf);

	if (xf)
		xfile_close(xf);

#if defined(_DEBUG) || defined(DEBUG)
	XDK_TRACE_LAST;
#endif

	return 0;
}

bool_t	save_dom_doc_to_file(link_t_ptr dom, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr xml;
	bool_t rt;

	xml = upcast_dom_to_xml(dom);
	rt = save_xml_doc_to_file(xml, psd, fname);
	downcast_xml_to_dom(xml);

	return rt;
}

bool_t	load_dom_doc_from_file(link_t_ptr dom, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr xml;
	bool_t rt;

	xml = upcast_dom_to_xml(dom);
	rt = load_xml_doc_from_file(xml, psd, fname);
	downcast_xml_to_dom(xml);

	return rt;
}

link_t_ptr	create_schema_doc_from_file(const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr ptr;

	ptr = create_dom_doc();
	if (!load_dom_doc_from_file(ptr, psd, fname))
	{
		destroy_dom_doc(ptr);
		return NULL;
	}

	if (compare_text(get_dom_node_name_ptr(ptr), -1, DOC_SCHEMA, -1, 1) != 0)
	{
		destroy_dom_doc(ptr);
		return NULL;
	}

	return ptr;
}

bool_t save_schema_doc_to_file(link_t_ptr ptr, const secu_desc_t* psd, const tchar_t* fname)
{
	return save_dom_doc_to_file(ptr, psd, fname);
}

link_t_ptr	create_images_from_meta_file(const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta, ptr;

	meta = create_meta_doc();
	if (!load_dom_doc_from_file(meta, psd, fname))
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	if (compare_text(get_meta_doc_name_ptr(meta), -1, DOC_IMAGES, -1, 1) != 0)
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return ptr;
}

bool_t save_images_to_meta_file(link_t_ptr ptr, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta;
	bool_t rt;

	meta = create_meta_doc();

	attach_meta_body_node(meta, ptr);

	rt = save_dom_doc_to_file(meta, psd, fname);

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return rt;
}

link_t_ptr	create_form_from_meta_file(const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta,ptr;

	meta = create_meta_doc();
	if (!load_dom_doc_from_file(meta, psd, fname))
	{
		destroy_meta_doc(meta);
		return NULL;
	}
	
	if (compare_text(get_meta_doc_name_ptr(meta), -1, DOC_FORM, -1, 1) != 0)
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return ptr;
}

bool_t save_form_to_meta_file(link_t_ptr ptr, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta;
	bool_t rt;

	meta = create_meta_doc();

	attach_meta_body_node(meta, ptr);

	rt = save_dom_doc_to_file(meta, psd, fname);

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return rt;
}

link_t_ptr	create_grid_from_meta_file(const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta, ptr;

	meta = create_meta_doc();
	if (!load_dom_doc_from_file(meta, psd, fname))
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	if (compare_text(get_meta_doc_name_ptr(meta), -1, DOC_GRID, -1, 1) != 0)
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return ptr;
}

bool_t save_grid_to_meta_file(link_t_ptr ptr, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta;
	bool_t rt;

	meta = create_meta_doc();

	attach_meta_body_node(meta, ptr);

	rt = save_dom_doc_to_file(meta, psd, fname);

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return rt;
}

link_t_ptr	create_statis_from_meta_file(const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta, ptr;

	meta = create_meta_doc();
	if (!load_dom_doc_from_file(meta, psd, fname))
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	if (compare_text(get_meta_doc_name_ptr(meta), -1, DOC_STATIS, -1, 1) != 0)
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return ptr;
}

bool_t save_statis_to_meta_file(link_t_ptr ptr, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta;
	bool_t rt;

	meta = create_meta_doc();

	attach_meta_body_node(meta, ptr);

	rt = save_dom_doc_to_file(meta, psd, fname);

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return rt;
}

link_t_ptr	create_dialog_from_meta_file(const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta, ptr;

	meta = create_meta_doc();
	if (!load_dom_doc_from_file(meta, psd, fname))
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	if (compare_text(get_meta_doc_name_ptr(meta), -1, DOC_DIALOG, -1, 1) != 0)
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return ptr;
}

bool_t save_dialog_to_meta_file(link_t_ptr ptr, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta;
	bool_t rt;

	meta = create_meta_doc();

	attach_meta_body_node(meta, ptr);

	rt = save_dom_doc_to_file(meta, psd, fname);

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return rt;
}

link_t_ptr	create_calendar_from_meta_file(const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta, ptr;

	meta = create_meta_doc();
	if (!load_dom_doc_from_file(meta, psd, fname))
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	if (compare_text(get_meta_doc_name_ptr(meta), -1, DOC_DIAGRAM, -1, 1) != 0)
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return ptr;
}

bool_t save_calendar_to_meta_file(link_t_ptr ptr, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta;
	bool_t rt;

	meta = create_meta_doc();

	attach_meta_body_node(meta, ptr);

	rt = save_dom_doc_to_file(meta, psd, fname);

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return rt;
}

link_t_ptr	create_diagram_from_meta_file(const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta, ptr;

	meta = create_meta_doc();
	if (!load_dom_doc_from_file(meta, psd, fname))
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	if (compare_text(get_meta_doc_name_ptr(meta), -1, DOC_DIAGRAM, -1, 1) != 0)
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return ptr;
}

bool_t save_diagram_to_meta_file(link_t_ptr ptr, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta;
	bool_t rt;

	meta = create_meta_doc();

	attach_meta_body_node(meta, ptr);

	rt = save_dom_doc_to_file(meta, psd, fname);

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return rt;
}

link_t_ptr	create_topog_from_meta_file(const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta, ptr;

	meta = create_meta_doc();
	if (!load_dom_doc_from_file(meta, psd, fname))
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	if (compare_text(get_meta_doc_name_ptr(meta), -1, DOC_TOPOG, -1, 1) != 0)
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return ptr;
}

bool_t save_topog_to_meta_file(link_t_ptr ptr, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta;
	bool_t rt;

	meta = create_meta_doc();

	attach_meta_body_node(meta, ptr);

	rt = save_dom_doc_to_file(meta, psd, fname);

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return rt;
}

link_t_ptr	create_plot_from_meta_file(const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta, ptr;

	meta = create_meta_doc();
	if (!load_dom_doc_from_file(meta, psd, fname))
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	if (compare_text(get_meta_doc_name_ptr(meta), -1, DOC_PLOT, -1, 1) != 0)
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return ptr;
}

bool_t save_plot_to_meta_file(link_t_ptr ptr, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta;
	bool_t rt;

	meta = create_meta_doc();

	attach_meta_body_node(meta, ptr);

	rt = save_dom_doc_to_file(meta, psd, fname);

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return rt;
}

link_t_ptr	create_rich_from_meta_file(const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta, ptr;

	meta = create_meta_doc();
	if (!load_dom_doc_from_file(meta, psd, fname))
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	if (compare_text(get_meta_doc_name_ptr(meta), -1, DOC_RICH, -1, 1) != 0)
	{
		destroy_meta_doc(meta);
		return NULL;
	}

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return ptr;
}

bool_t save_rich_to_meta_file(link_t_ptr ptr, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr meta;
	bool_t rt;

	meta = create_meta_doc();

	attach_meta_body_node(meta, ptr);

	rt = save_dom_doc_to_file(meta, psd, fname);

	ptr = detach_meta_body_node(meta);
	destroy_meta_doc(meta);

	return rt;
}

