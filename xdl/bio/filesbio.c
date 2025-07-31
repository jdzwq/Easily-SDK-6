/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc file document

	@module	file.c | implement file

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

#include "filesbio.h"

#include "../xdldoc.h"

static void _list_file(const file_info_t* pfi, void* pa)
{
	link_t_ptr ptr = (link_t_ptr)pa;
	link_t_ptr nlk;

	if (pfi->is_dir)
		nlk = insert_list_directory_item(ptr, LINK_LAST);
	else
		nlk = insert_list_file_item(ptr, LINK_LAST);

	set_list_item_file_info(nlk, pfi);
}

bool_t xfile_list(const secu_desc_t* psd, const tchar_t* path, link_t_ptr ptr)
{
	byte_t proto;

	if (is_null(path))
		return 0;

	proto = parse_proto(path);

	if (IS_INET_FILE(proto))
	{
#if defined(XDK_SUPPORT_SOCK) 
		return xnetf_list_file(psd, path, _list_file, (void*)ptr);
#else
		return 0;
#endif
	}
	if (!IS_INET_FILE(proto))
	{
#if defined(XDK_SUPPORT_FILE)
		return xuncf_list_file(psd, path, _list_file, (void*)ptr);
#else
		return 0;
#endif
	}

	return 0;
}

void xfile_tree(const secu_desc_t* psd, const tchar_t* path, link_t_ptr ptr)
{
	link_t_ptr nlk;
	tchar_t file[PATH_LEN + 1] = { 0 };
	tchar_t* token;

	xsncpy(file, path, PATH_LEN);
	xscat(file, _T("/*.*"));

	xfile_list(psd, file, ptr);

	nlk = get_list_first_child_item(ptr);
	while (nlk)
	{
		if (is_list_directory_item(nlk))
		{
			token = file + xslen(file);
			while (*token != _T('/') && *token != _T('\\') && token != file)
				*(token--) = _T('\0');

			*token = _T('/');
			xscat(token, get_list_item_file_name_ptr(nlk));

			xfile_tree(psd, file, nlk);
		}

		nlk = get_list_next_sibling_item(nlk);
	}
}


static void _dump_file(const file_info_t* pfi, void* pa)
{
	stream_t stm = (stream_t)pa;

	string_t vs = NULL;
	dword_t pos = 0;
	tchar_t feed[3] = { TXT_ITEMFEED, TXT_LINEFEED, _T('\n') };
	tchar_t ftime[DATE_LEN + 1];
	tchar_t fsize[NUM_LEN + 1];
	tchar_t fetag[KEY_LEN + 1];

	vs = string_alloc();

	if (pfi->is_dir)
		string_cat(vs, DOC_LIST_DIRECTORY, -1);
	else
		string_cat(vs, DOC_LIST_FILE, -1);

	string_cat(vs, feed, 1);

	string_cat(vs, pfi->file_name, -1);
	string_cat(vs, feed, 1);

	format_gmttime(&pfi->create_time, ftime);
	string_cat(vs, ftime, -1);
	string_cat(vs, feed, 1);

	format_gmttime(&pfi->access_time, ftime);
	string_cat(vs, ftime, -1);
	string_cat(vs, feed, 1);

	format_gmttime(&pfi->write_time, ftime);
	string_cat(vs, ftime, -1);
	string_cat(vs, feed, 1);

	if (pfi->is_dir)
		xscpy(fsize, _T(""));
	else
		format_long(pfi->high_size, pfi->low_size, fsize);

	string_cat(vs, fsize, -1);
	string_cat(vs, feed, 1);

	if (pfi->is_dir)
		xscpy(fetag, _T(""));
	else
		xscpy(fetag, pfi->file_etag);

	string_cat(vs, fetag, -1);
	string_cat(vs, feed, 1);

	string_cat(vs, feed + 1, 2);

	pos = 0;
	stream_write_line(stm, vs, &pos);

	string_free(vs);
}

bool_t xfile_dump(const secu_desc_t* psd, const tchar_t* path, stream_t stm)
{
	byte_t proto;
	bool_t b = 0;

	stream_write_utfbom(stm, NULL);

	if (!is_null(path))
	{
		proto = parse_proto(path);

		if (IS_INET_FILE(proto))
		{
#if defined(XDK_SUPPORT_SOCK)
			b = xnetf_list_file(psd, path, _dump_file, (void*)stm);
#endif
		}
		if (!IS_INET_FILE(proto))
		{
#if defined(XDK_SUPPORT_FILE)
			b = xuncf_list_file(psd, path, _dump_file, (void*)stm);
#endif
		}
	}

	stream_write_line(stm, NULL, NULL);

	return stream_flush(stm);
}
