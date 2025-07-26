
#ifndef _XDKSTD_H
#define _XDKSTD_H

#include "xdkdef.h"
#include "xdkinit.h"

#include "acp/acp.h"

#include "enc/der.h"
#include "enc/base64.h"
#include "enc/conv.h"
#include "enc/escape.h"

#include "str/str.h"
#include "str/strext.h"
#include "str/strutil.h"

#include "maa/bytearray.h"
#include "maa/stringarray.h"
#include "maa/integerarray.h"
#include "maa/numericarray.h"

#include "util/calendar.h"
#include "util/charset.h"
#include "util/compare.h"
#include "util/dbllink.h"
#include "util/money.h"
#include "util/numbers.h"
#include "util/nuid.h"
#include "util/optparser.h"
#include "util/others.h"
#include "util/prim.h"
#include "util/solarterms.h"
#include "util/sort.h"

#include "imp/platimp.h"
#include "imp/impjmp.h"
#include "imp/impmem.h"
#include "imp/impassert.h"
#include "imp/imperror.h"
#include "imp/impblock.h"

#ifdef XDK_SUPPORT_MBCS
#include "imp/impmbcs.h"
#endif

#ifdef XDK_SUPPORT_DATE
#include "imp/impdate.h"
#endif

#ifdef XDK_SUPPORT_ASYNC
#include "imp/impasync.h"
#endif

#ifdef XDK_SUPPORT_THREAD
#include "imp/impthr.h"
#endif

#ifdef XDK_SUPPORT_TIMER
#include "imp/imptimer.h"
#endif

#ifdef XDK_SUPPORT_RANDOM
#include "imp/imprandom.h"
#endif

#ifdef XDK_SUPPORT_FILE
#include "imp/impuncf.h"
#endif

#ifdef XDK_SUPPORT_SOCK
#include "imp/impsock.h"
#endif

#ifdef XDK_SUPPORT_SHARE
#include "imp/impshare.h"
#endif

#ifdef XDK_SUPPORT_MEMO_CACHE
#include "imp/impcache.h"
#endif

#ifdef XDK_SUPPORT_PROCESS
#include "imp/impproc.h"
#endif

#ifdef XDK_SUPPORT_PIPE
#include "imp/imppipe.h"
#endif

#ifdef XDK_SUPPORT_COMM
#include "imp/impcomm.h"
#endif

#ifdef XDK_SUPPORT_CONS
#include "imp/impcons.h"
#endif


#endif //_XDKSTD_H
