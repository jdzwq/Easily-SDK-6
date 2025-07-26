/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdk interface document

	@module	impplat.h | interface file

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

#ifndef _IMPPLAT_H
#define	_IMPPLAT_H

#include "../xdkdef.h"


#ifdef	__cplusplus
extern "C" {
#endif

#ifdef XDK_SUPPORT_MEMO
	EXP_API void xdk_impl_memo_local(if_memo_t* pif);
#ifdef XDK_SUPPORT_MEMO_HEAP
	EXP_API void xdk_impl_memo_heap(if_memo_t* pif);
#endif
#ifdef XDK_SUPPORT_MEMO_PAGE
	EXP_API void xdk_impl_memo_page(if_memo_t* pif);
#endif
#ifdef XDK_SUPPORT_MEMO_CACHE
	EXP_API void xdk_impl_memo_cache(if_memo_t* pif);
#endif
#endif /*XDK_SUPPORT_MEMO*/

#ifdef XDK_SUPPORT_ERROR
	EXP_API void xdk_impl_error(if_error_t* pif);
#endif

#ifdef XDK_SUPPORT_MBCS
	EXP_API void xdk_impl_mbcs(if_mbcs_t* pif);
#endif

#ifdef XDK_SUPPORT_ASYNC
	EXP_API void xdk_impl_async(if_async_t* pif);
#endif

#ifdef XDK_SUPPORT_THREAD
	EXP_API void xdk_impl_thread(if_thread_t* pif);
#ifdef XDK_SUPPORT_THREAD_EVENT
	EXP_API void xdk_impl_thread_event(if_thread_t* pif);
#endif
#ifdef XDK_SUPPORT_THREAD_CRITI
	EXP_API void xdk_impl_thread_criti(if_thread_t* pif);
#endif
#ifdef XDK_SUPPORT_THREAD_MUTEX
	EXP_API void xdk_impl_thread_mutex(if_thread_t* pif);
#endif
#ifdef XDK_SUPPORT_THREAD_SEMAP
	EXP_API void xdk_impl_thread_semap(if_thread_t* pif);
#endif
#ifdef XDK_SUPPORT_THREAD_QUEUE
	EXP_API void xdk_impl_thread_queue(if_thread_t* pif);
#endif
#endif /*XDK_SUPPORT_THREAD*/

#ifdef XDK_SUPPORT_TIMER
	EXP_API void xdk_impl_timer(if_timer_t* pif);
#endif

#ifdef XDK_SUPPORT_RANDOM
	EXP_API void xdk_impl_random(if_random_t* pif);
#endif

#ifdef XDK_SUPPORT_FILE
	EXP_API void xdk_impl_file(if_file_t* pif);
#ifdef XDK_SUPPORT_FILE_FIND
	EXP_API void xdk_impl_file_find(if_file_t* pif);
#endif
#endif /*XDK_SUPPORT_FILE*/

#ifdef XDK_SUPPORT_SHARE
	EXP_API void xdk_impl_share(if_share_t* pif);
#endif

#ifdef XDK_SUPPORT_PIPE
	EXP_API void xdk_impl_pipe(if_pipe_t* pif);
#endif

#ifdef XDK_SUPPORT_COMM
	EXP_API void xdk_impl_comm(if_comm_t* pif);
#endif

#ifdef XDK_SUPPORT_CONS
	EXP_API void xdk_impl_cons(if_cons_t* pif);
#endif

#ifdef XDK_SUPPORT_SOCK
	EXP_API void xdk_impl_socket(if_socket_t* pif);
#endif

#ifdef XDK_SUPPORT_DATE
	EXP_API void xdk_impl_date(if_date_t* pif);
#endif

#ifdef XDK_SUPPORT_PROCESS
	EXP_API void xdk_impl_process(if_process_t* pif);
#endif


#ifdef	__cplusplus
}
#endif

#endif	/* _XDKINF_H */

