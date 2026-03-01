/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc uio interface document

	@module	uioinf.c | implement file

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

#include "uioimp.h"

#include "../xdkimp.h"
#include "../xdknet.h"

static bool_t _push_line(xhand_t io, const byte_t* buf, dword_t* plen)
{
	xuncf_seek_end(io);

	*plen = xuncf_write_line(io, buf, *plen);

	return (*plen)? bool_true : bool_false;
}

static bool_t _pop_line(xhand_t io, byte_t* buf, dword_t* plen)
{
	vlong_t pos;

	xuncf_seek_end(io);

	pos = xuncf_seek_lines(io, -1);
	if(pos < 0) return bool_false;

	*plen  = xuncf_read_line(io, buf, *plen);

	xuncf_truncate(io, pos);

	return (*plen)? bool_true : bool_false;
}

static bool_t _peek_line(xhand_t io, byte_t* buf, dword_t* plen)
{
	vlong_t len;

	xuncf_seek_end(io);

	xuncf_seek_lines(io, -1);

	*plen = xuncf_read_line(io, buf, *plen);

	return (*plen)? bool_true : bool_false;
}

static void _close(xhand_t io)
{
	xuncf_close_file(io);
}

bool_t get_uio_interface(xhand_t io, uio_interface* pio)
{
	XDK_ASSERT(io->tag == _HANDLE_UNCF);

	pio->fd = io;
	
	pio->pf_close = _close;
	pio->pf_peek = _peek_line;
	pio->pf_pop = _pop_line;
	pio->pf_push = _push_line;
	
	return bool_true;
}
