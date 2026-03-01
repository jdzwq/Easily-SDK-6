/***********************************************************************
	Easily xdk v5.5

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc async system call document

	@module	_if_async.c | async system call windows implement file

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

#include "../xdkloc.h"

#ifdef XDK_SUPPORT_ASYNC

typedef struct OVERLAPPED{
    union{
        struct timeval tv;
        struct timespec tp;
    };
    
    union{
        struct fd_set fs[MAX_EVENT];
        struct kevent ev[MAX_EVENT];
    };
}OVERLAPPED, *LPOVERLAPPED;

void _async_init(async_t* pas, int type, int ms, res_file_t fd)
{
#ifdef XDK_SUPPORT_THREAD_QUEUE
    if (type == ASYNC_QUEUE)
        pas->port = _queue_create((res_queue_t)0, fd, 0);
    else
        pas->port = (res_queue_t)0;
#endif
	
	pas->type = type;
    pas->timo = (ms < 0)? INFINITE : ms;
}

void _async_uninit(async_t* pas)
{
#ifdef XDK_SUPPORT_THREAD_QUEUE
    if (pas->type == ASYNC_QUEUE && pas->port)
    {
        _queue_destroy(pas->port);
    }
#endif
}

#endif //XDK_SUPPORT_ASYNC

