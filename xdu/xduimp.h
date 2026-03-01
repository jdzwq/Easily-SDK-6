
#ifndef _XDUIMP_H
#define _XDUIMP_H

#ifdef XDU_SUPPORT_SHELL
#include "imp/impshell.h"
#endif

#ifdef XDU_SUPPORT_CONTEXT_BITMAP
#include "imp/impbitmap.h"
#endif

#ifdef XDU_SUPPORT_CLIPBOARD
#include "imp/impclip.h"
#endif

#ifdef XDU_SUPPORT_CONTEXT
#include "imp/impcontext.h"
#include "imp/impgdi.h"
#include "imp/gdicanv.h"
#include "inf/gdiinf.h"
#endif

#ifdef XDU_SUPPORT_WIDGET
#include "imp/impwidget.h"
#endif



#endif //_XDUIMP_H
