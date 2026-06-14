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

#if defined(_COCOA)
#include "cocoa/_if_cocoa.h"
#elif defined(_XQUARTZ)
#include "xquartz/_if_xquartz.h"
#endif

#ifdef XDU_SUPPORT_CLIPBOARD

bool_t _clipboard_put(widget_t wt, int fmt, const byte_t* data, dword_t size)
{
#if defined(_COCOA)
	return coClipboardPut(wt, fmt, data, size);
#elif defined(_XQUARTZ)
	return xqClipboardPut(wt, fmt, data, size);
#endif
}

dword_t _clipboard_get(widget_t wt, int fmt, byte_t* buf, dword_t max)
{
#if defined(_COCOA)
	return coClipboardGet(wt, fmt, buf, max);
#elif defined(_XQUARTZ)
	return xqClipboardGet(wt, fmt, buf, max);
#endif
}


#endif //XDU_SUPPORT_CLIPBOARD