/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdl image utility document

	@module	imagesbag.c | implement file

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

#include "imagesbio.h"

#include "../xdlbio.h"
#include "../xdldoc.h"


link_t_ptr insert_images_item_from_url(link_t_ptr ptr, const tchar_t* iname, const tchar_t* url)
{
	link_t_ptr nlk;

	if (is_null(iname))
		return NULL;

	nlk = get_images_item(ptr, iname, -1);
	if (!nlk)
	{
		nlk = insert_images_item(ptr, LINK_LAST);
		set_images_item_alt(nlk, iname);
	}

	set_images_item_src(nlk, url);

	return nlk;
}

link_t_ptr insert_images_item_from_file(link_t_ptr ptr, const tchar_t* iname, const secu_desc_t* psd, const tchar_t* fname)
{
	link_t_ptr nlk;
	dword_t size;
	byte_t *file_buf;
	int len,tlen;
	tchar_t* xbas_buf = NULL;
	tchar_t type[RES_LEN + 1] = { 0 };

	if (is_null(iname))
		return NULL;

	size = load_image_bytes_from_file(psd, fname, NULL, NULL, MAX_LONG);
	if (!size)
		return NULL;

	file_buf = (byte_t*)xmem_alloc(size);

	size = load_image_bytes_from_file(psd, fname, type, file_buf, size);
	if (!size)
	{
		xmem_free(file_buf);
		return NULL;
	}

	len = size;
	size = xbas_encode(file_buf, len, NULL, MAX_LONG);
	tlen = xslen(type);

	xbas_buf = xsalloc(tlen + size + 1);
	xsncpy(xbas_buf, type, tlen);

	xbas_encode(file_buf, len, xbas_buf + tlen, size);

	xmem_free(file_buf);

	nlk = get_images_item(ptr, iname, -1);
	if (!nlk)
	{
		nlk = insert_images_item(ptr, LINK_LAST);
		set_images_item_alt(nlk, iname);
	}

	attach_dom_node_attr(nlk, ATTR_SRC, xbas_buf);

	return nlk;
}
