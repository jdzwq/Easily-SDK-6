/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc shell document

	@module	wl_shell.c | wayland implement file

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

#include "_if_wayland.h"


bool_t wlShellGetFileName(widget_t owner, const tchar_t* defpath, const tchar_t* filter, const tchar_t* defext, bool_t saveit, tchar_t* pathbuf, int pathlen, tchar_t* filebuf, int filelen)
{
    return 0;
}

bool_t wlShellGetPathName(widget_t owner, const tchar_t* defpath, bool_t createit, tchar_t* pathbuf, int pathlen)
{
    return 0;
}

bool_t wlShellGetCurPath(tchar_t* pathbuf, int pathlen)
{
	if (getcwd(pathbuf, pathlen)) {
        return 1;
    }
    pathbuf[0] = 0;
    return 0;
}

bool_t wlShellGetRunPath(tchar_t* pathbuf, int pathlen)
{
	char exe_path[PATH_MAX];
    char* last_slash;

    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) {
        pathbuf[0] = 0;
        return 0;
    }
    exe_path[len] = 0;
    last_slash = strrchr(exe_path, '/');
    if (last_slash) {
        *last_slash = 0;
        strncpy(pathbuf, exe_path, pathlen - 1);
        pathbuf[pathlen - 1] = 0;
        return 1;
    }
    pathbuf[0] = 0;
    return 0;
}

bool_t wlShellGetAppPath(tchar_t* pathbuf, int pathlen)
{
	char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    
    if (len <= 0) {
        pathbuf[0] = 0;
        return 0;
    }
    exe_path[len] = 0;
    strncpy(pathbuf, exe_path, pathlen - 1);
    pathbuf[pathlen - 1] = 0;
    return 1;
}

bool_t wlShellGetDocPath(tchar_t* pathbuf, int pathlen)
{
	const char* home = getenv("HOME");
    if (!home) {
        pathbuf[0] = 0;
        return 0;
    }
    snprintf(pathbuf, pathlen, "%s/Documents", home);
    pathbuf[pathlen - 1] = 0;
    return 1;
}

bool_t wlShellGetTmpPath(tchar_t* pathbuf, int pathlen)
{
	const char* tmp = getenv("TMPDIR");
    if (!tmp || !tmp[0]) {
        tmp = "/tmp";
    }
    strncpy(pathbuf, tmp, pathlen - 1);
    pathbuf[pathlen - 1] = 0;
    return 1;
}
