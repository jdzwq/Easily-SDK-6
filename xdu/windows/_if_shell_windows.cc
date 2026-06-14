/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc shell document

	@module	_if_shell_win.c | widnows implement file

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

#if defined(_WCE)
#include "wince/_if_wince.h"
#elif defined(_W32)
#include "win32/_if_win32.h"
#endif

#ifdef XDU_SUPPORT_SHELL

bool_t _shell_get_filename(widget_t owner, const tchar_t* defpath, const tchar_t* filter, const tchar_t* defext, bool_t saveit, tchar_t* pathbuf, int pathlen, tchar_t* filebuf, int filelen)
{
#if defined(WINCE)
	return wceShellGetFileName(owner, defpath, filter, defext, saveit, pathbuf, pathlen, filebuf, filelen);
#elif defined(WIN32)
	return winShellGetFileName(owner, defpath, filter, defext, saveit, pathbuf, pathlen, filebuf, filelen);
#endif
}

bool_t _shell_get_pathname(widget_t owner, const tchar_t* defpath, bool_t createit, tchar_t* pathbuf, int pathlen)
{
#if defined(WINCE)
	return wceShellGetPathName(owner, defpath, createit, pathbuf, pathlen);
#elif defined(WIN32)
	return winShellGetPathName(owner, defpath, createit, pathbuf, pathlen);
#endif
}

bool_t _shell_get_curpath(tchar_t* pathbuf, int pathlen)
{
#if defined(WINCE)
	return wceShellGetCurPath(pathbuf, pathlen);
#elif defined(WIN32)
	return winShellGetCurPath(pathbuf, pathlen);
#endif
}

bool_t _shell_get_runpath(tchar_t* pathbuf, int pathlen)
{
#if defined(WINCE)
	return wceShellGetRunPath(pathbuf, pathlen);
#elif defined(WIN32)
	return winShellGetRunPath(pathbuf, pathlen);
#endif
}

bool_t _shell_get_apppath(tchar_t* pathbuf, int pathlen)
{
#if defined(WINCE)
	return wceShellGetAppPath(pathbuf, pathlen);
#elif defined(WIN32)
	return winShellGetAppPath(pathbuf, pathlen);
#endif
}

bool_t _shell_get_docpath(tchar_t* pathbuf, int pathlen)
{
#if defined(WINCE)
	return wceShellGetDocPath(pathbuf, pathlen);
#elif defined(WIN32)
	return winShellGetDocPath(pathbuf, pathlen);
#endif
}

bool_t _shell_get_tmppath(tchar_t* pathbuf, int pathlen)
{
#if defined(WINCE)
	return wceShellGetTmpPath(pathbuf, pathlen);
#elif defined(WIN32)
	return winShellGetTmpPath(pathbuf, pathlen);
#endif
}

#endif /*XDU_SUPPORT_SHELL*/