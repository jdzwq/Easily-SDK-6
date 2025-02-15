
#ifndef _XDCIMP_H
#define _XDCIMP_H

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
#include "imp/gdiface.h"
#endif

#ifdef XDU_SUPPORT_WIDGET
#include "imp/impwidget.h"
#include "imp/widgetnc.h"
#include "imp/widgetex.h"

#include "hand/docker.h"
#include "hand/splitor.h"
#include "hand/textor.h"

#include "box/box.h"
#include "edit/editor.h"
#include "ctrl/ctrl.h"
#include "dlg/dlg.h"
#include "menu/menu.h"

#endif



#endif //_XDCIMP_H
