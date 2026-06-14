/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc shell document

	@module	if_shell.c | linux implement file

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

#include "../xduloc.h"

#if defined(_X11)
#include "X11/_if_x11.h"
#elif defined(_WAYLAND)
#include "wayland/_if_wayland.h"
#endif

#ifdef XDU_SUPPORT_SHELL

bool_t _shell_get_filename(widget_t owner, const tchar_t* defpath, const tchar_t* filter, const tchar_t* defext, bool_t saveit, tchar_t* pathbuf, int pathlen, tchar_t* filebuf, int filelen)
{
#if defined(_X11)
	return xlShellGetFileName(owner, defpath, filter, defext, saveit, pathbuf, pathlen, filebuf, filelen);
#elif defined(_WAYLAND)
	return wlShellGetFileName(owner, defpath, filter, defext, saveit, pathbuf, pathlen, filebuf, filelen);
#endif
}

bool_t _shell_get_pathname(widget_t owner, const tchar_t* defpath, bool_t createit, tchar_t* pathbuf, int pathlen)
{
#if defined(_X11)
	return xlShellGetPathName(owner, defpath, createit, pathbuf, pathlen);
#elif defined(_WAYLAND)
	return wlShellGetPathName(owner, defpath, createit, pathbuf, pathlen);
#endif
}

bool_t _shell_get_curpath(tchar_t* pathbuf, int pathlen)
{
#if defined(_X11)
	return xlShellGetCurPath(pathbuf, pathlen);
#elif defined(_WAYLAND)
	return wlShellGetCurPath(pathbuf, pathlen);
#endif
}

bool_t _shell_get_runpath(tchar_t* pathbuf, int pathlen)
{
#if defined(_X11)
	return xlShellGetRunPath(pathbuf, pathlen);
#elif defined(_WAYLAND)
	return wlShellGetRunPath(pathbuf, pathlen);
#endif
}

bool_t _shell_get_apppath(tchar_t* pathbuf, int pathlen)
{
#if defined(_X11)
	return xlShellGetAppPath(pathbuf, pathlen);
#elif defined(_WAYLAND)
	return wlShellGetAppPath(pathbuf, pathlen);
#endif
}

bool_t _shell_get_docpath(tchar_t* pathbuf, int pathlen)
{
#if defined(_X11)
	return xlShellGetDocPath(pathbuf, pathlen);
#elif defined(_WAYLAND)
	return wlShellGetDocPath(pathbuf, pathlen);
#endif
}

bool_t _shell_get_tmppath(tchar_t* pathbuf, int pathlen)
{
#if defined(_X11)
	return xlShellGetTmpPath(pathbuf, pathlen);
#elif defined(_WAYLAND)
	return wlShellGetTmpPath(pathbuf, pathlen);
#endif
}

#endif /*XDU_SUPPORT_SHELL*/