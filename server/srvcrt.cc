
/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, China ZheJiang HangZhou JianDe, Mail: powersuite@hotmaol.com

	@doc service cert document

	@module	srvcert.cc | service cert implement file

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

#include "srvcrt.h"

bool_t get_ssl_crt(const tchar_t* path, const tchar_t* name, byte_t* buf, dword_t* pb)
{
	tchar_t sz_file[PATH_LEN + 1] = { 0 };
	tchar_t sz_size[NUM_LEN + 1] = { 0 };

	file_t xf;
	dword_t n_size;

	xsprintf(sz_file, _T("%s/crt/%s.crt"), path, name);
	if (!xfile_info(NULL, sz_file, NULL, sz_size, NULL, NULL))
	{
		*pb = 0;
		return 0;
	}

	n_size = xstol(sz_size);
	n_size = (n_size < *pb) ? n_size : *pb;

	xf = xfile_open(NULL, sz_file, FILE_OPEN_READ);
	if (!xf)
	{
		*pb = 0;
		return 0;
	}

	if (!xfile_read(xf, buf, n_size))
	{
		xfile_close(xf);

		*pb = 0;
		return 0;
	}

	xfile_close(xf);
	
	*pb = n_size;
	return 1;
}

bool_t get_ssl_key(const tchar_t* path, const tchar_t* name, byte_t* buf, dword_t* pb)
{
	tchar_t sz_file[PATH_LEN + 1] = { 0 };
	tchar_t sz_size[NUM_LEN + 1] = { 0 };

	file_t xf;
	dword_t n_size;

	xsprintf(sz_file, _T("%s/crt/%s.key"), path, name);
	if (!xfile_info(NULL, sz_file, NULL, sz_size, NULL, NULL))
	{
		*pb = 0;
		return 0;
	}

	n_size = xstol(sz_size);
	n_size = (n_size < *pb) ? n_size : *pb;

	xf = xfile_open(NULL, sz_file, FILE_OPEN_READ);
	if (!xf)
	{
		*pb = 0;
		return 0;
	}

	if (!xfile_read(xf, buf, n_size))
	{
		xfile_close(xf);

		*pb = 0;
		return 0;
	}

	xfile_close(xf);

	*pb = n_size;
	return 1;
}

bool_t get_ssh_key(const tchar_t* path, const tchar_t* name, byte_t* buf, dword_t* pb)
{
	tchar_t sz_file[PATH_LEN + 1] = { 0 };
	tchar_t sz_size[NUM_LEN + 1] = { 0 };

	file_t xf;
	dword_t n_size;

	xsprintf(sz_file, _T("%s/crt/%s.key"), path, name);
	if (!xfile_info(NULL, sz_file, NULL, sz_size, NULL, NULL))
	{
		*pb = 0;
		return 0;
	}

	n_size = xstol(sz_size);
	n_size = (n_size < *pb) ? n_size : *pb;

	xf = xfile_open(NULL, sz_file, FILE_OPEN_READ);
	if (!xf)
	{
		*pb = 0;
		return 0;
	}

	if (!xfile_read(xf, buf, n_size))
	{
		xfile_close(xf);

		*pb = 0;
		return 0;
	}

	xfile_close(xf);

	*pb = n_size;
	return 1;
}
