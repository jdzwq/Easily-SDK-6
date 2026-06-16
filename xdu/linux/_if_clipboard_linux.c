/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc clipboard document

	@module	if_clipboard.c | linux implement file

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
#include "X11/_if_X11.h"
#elif defined(_WAYLAND)
#include "wayland/_if_wayland.h"
#endif

#ifdef XDU_SUPPORT_CLIPBOARD

bool_t _clipboard_put(widget_t wt, int fmt, const byte_t* data, dword_t size)
{
#if defined(_X11)
	return xlClipboardPut(wt, fmt, data, size);
#elif defined(_WAYLAND)
	return wlClipboardPut(wt, fmt, data, size);
#endif
}

dword_t _clipboard_get(widget_t wt, int fmt, byte_t* buf, dword_t max)
{
#if defined(_X11)
	return xlClipboardGet(wt, fmt, buf, max);
#elif defined(_WAYLAND)
	return wlClipboardGet(wt, fmt, buf, max);
#endif
}


#endif //XDU_SUPPORT_CLIPBOARD