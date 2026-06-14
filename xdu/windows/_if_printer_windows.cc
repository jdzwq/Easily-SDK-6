/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc device printer document

	@module	if_printer_win.c | windows implement file

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

#if defined(WIN32)
#include "win32/_if_win32.h"
#endif

#ifdef XDU_SUPPORT_CONTEXT_PRINTER

bool_t _default_printer_mode(dev_prn_t* pmod)
{
#if defined(WIN32)
	return winDefaultPrinterMode(pmod);
#endif
}

bool_t _setup_printer_mode(widget_t wt, dev_prn_t* pmod)
{
#if defined(WIN32)
	return winSetupPrinterMode(wt, pmod);
#endif
}

visual_t _create_printer_context(const dev_prn_t* pmod)
{
#if defined(WIN32)
	return winCreatePrinterContext(pmod);
#endif
}

void _destroy_printer_context(visual_t rdc)
{
#if defined(WIN32)
	winDestroyPrinterContext(rdc);
#endif
}

void _begin_page(visual_t rdc)
{
#if defined(WIN32)
	winBeginPage(rdc);
#endif
}

void _end_page(visual_t rdc)
{
#if defined(WIN32)
	winEndPage(rdc);
#endif
}

void _begin_doc(visual_t rdc, const tchar_t* docname)
{
#if defined(WIN32)
	winBeginDoc(rdc, docname);
#endif
}

void _end_doc(visual_t rdc)
{
#if defined(WIN32)
	winEndDoc(rdc);
#endif
}

#endif //XDU_SUPPORT_CONTEXT_PRINTER
