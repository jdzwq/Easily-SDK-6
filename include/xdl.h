
#ifndef _XDL_H
#define _XDL_H

#include "../xdl/xdldef.h"
#include "../xdl/xdlbio.h"
#include "../xdl/xdloop.h"
#include "../xdl/xdldoc.h"
#include "../xdl/xdlgdi.h"
#include "../xdl/xdlview.h"
#include "../xdl/xdlutil.h"

typedef	link_t_ptr	LINKPTR;
typedef xhand_t		XHANDLE;

#ifdef _OS_WINDOWS
#pragma comment(lib,"xdl.lib")
#endif

#endif //_XDL_H
