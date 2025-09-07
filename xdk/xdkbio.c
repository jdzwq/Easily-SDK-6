/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc bio interface document

	@module	bioinf.c | implement file

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

#include "xdkbio.h"

#include "xdkimp.h"

bool_t xdk_bio_interface(xhand_t io, bio_interface* pio)
{
	pio->fd = io;
	
	switch (io->tag)
	{
	case _HANDLE_BLOCK:
		pio->pf_read = xblock_read;
		pio->pf_write = xblock_write;
		return 1;
		break;
#ifdef XDK_SUPPORT_PIPE
	case _HANDLE_PIPE:
		pio->pf_read = xpipe_read;
		pio->pf_write = xpipe_write;
		pio->pf_flush = xpipe_flush;
		return 1;
		break;
#endif
#ifdef XDK_SUPPORT_COMM
	case _HANDLE_COMM:
		pio->pf_read = xcomm_read;
		pio->pf_write = xcomm_write;
		pio->pf_flush = xcomm_flush;
		return 1;
		break;
#endif
#ifdef XDK_SUPPORT_CONS
	case _HANDLE_CONS:
		pio->pf_read = xcons_read;
		pio->pf_write = xcons_write;
		pio->pf_flush = xcons_flush;
		return 1;
		break;
#endif
#ifdef XDK_SUPPORT_MEMO_CACHE
	case _HANDLE_CACHE:
		pio->pf_read = xcache_read;
		pio->pf_write = xcache_write;
		return 1;
		break;
#endif
#ifdef XDK_SUPPORT_SHARE
	case _HANDLE_SHARE:
		pio->pf_read = xshare_read;
		pio->pf_write = xshare_write;
		return 1;
		break;
#endif
	case _HANDLE_UNCF:
#ifdef XDK_SUPPORT_FILE
		pio->pf_read = xuncf_read_file;
		pio->pf_write = xuncf_write_file;
		pio->pf_flush = xuncf_flush_file;
		return 1;
		break;
#endif
	}

	return 0;
}
