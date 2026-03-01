/***********************************************************************
	Easily xdk v5.5

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc timer system call document

	@module	_if_timer.c | timer system call macos implement file

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

#ifdef XDK_SUPPORT_TIMER

#define MAX_TIMER_LISTEN	64

typedef struct _timer_token_t{
	int queue;

	PF_TIMERFUNC pf;
	void* pa;

	bool_t active;
	res_even_t ev;

	struct timespec due;
	struct timespec per;
}timer_token_t;

typedef struct _timer_queue_t{
	timer_token_t tt[MAX_TIMER_LISTEN];
}timer_queue_t;

void* _timer_listen(void* param)
{
	timer_token_t* ptt = (timer_token_t*)param;
	struct kevent event; 
	int rt;

	EV_SET(&event, 0, EVFILT_TIMER, EV_ADD | EV_CLEAR, 0, 0, NULL);

	if(kevent(ptt->queue, &event, 1, NULL, 0, NULL) == -1)
	{
		_event_sign(ptt->ev, 1);
		_thread_end();
	}

	if (kevent(ptt->queue, NULL, 0, &event, 1, &ptt->due) == -1)
	{
		_event_sign(ptt->ev, 1);
		_thread_end();
	}

	while (ptt->active)
	{
		rt = kevent(ptt->queue, NULL, 0, &event, 1, &ptt->per);
		if(rt == -1)
		{
			_event_sign(ptt->ev, 1);
			_thread_end();
		}

		if(event.flags & EV_ERROR)
		{
			_thread_sleep(1);
			continue;
		}

		if(rt > 0 && event.filter == EVFILT_TIMER)
		{
			if (ptt->pf)
			{
				(*(ptt->pf))(ptt->pa, (res_timer_t)ptt);
			}
		}
	}

	_event_sign(ptt->ev, 1);

	_thread_end();
}

res_queue_t _create_timer_queue()
{
	timer_queue_t* pqt;
	
	pqt = (timer_queue_t*)calloc(1, sizeof(timer_queue_t));
	
	return (res_queue_t)pqt;
}

void _destroy_timer_queue(res_queue_t rq)
{
	timer_queue_t* pqt = (timer_queue_t*)rq;
	int i;

	if(!rq) return;

	for(i = 0;i<MAX_TIMER_LISTEN;i++)
	{
		if(pqt->tt[i].active)
		{
			pqt->tt[i].active = 0;
			_event_wait(pqt->tt[i].ev, -1);
			_event_destroy(pqt->tt[i].ev);
		}

		if(pqt->tt[i].queue)
		{
			close(pqt->tt[i].queue);
		}
	}

	free(pqt);
}

res_timer_t _create_timer(res_queue_t rq, dword_t duetime, dword_t period, PF_TIMERFUNC pf, void* pa)
{
	timer_queue_t* pqt = (timer_queue_t*)rq;
	int i;
	res_thread_t th;

	if(!rq) return (res_timer_t)0;

	for(i = 0;i<MAX_TIMER_LISTEN;i++)
	{
		if(pqt->tt[i].queue == 0)
			break;
	}

	if(i == MAX_TIMER_LISTEN)
		return (res_timer_t)0;
	
	pqt->tt[i].queue = kqueue();
	if(pqt->tt[i].queue == 0)
		return (res_timer_t)0;

	pqt->tt[i].due.tv_sec = duetime / 1000;
	pqt->tt[i].due.tv_nsec = (duetime % 1000 ) * 1000000;
	pqt->tt[i].per.tv_sec = period / 1000;
	pqt->tt[i].per.tv_nsec = (period % 1000 ) * 1000000;

	pqt->tt[i].active = 1;
	pqt->tt[i].ev = _event_create();
	pqt->tt[i].pf = pf;
	pqt->tt[i].pa = pa;

	_thread_begin(&th, _timer_listen, (void*)&(pqt->tt[i]));

	return (res_timer_t)(&(pqt->tt[i]));
}

void _destroy_timer(res_queue_t rq, res_timer_t rt)
{
	timer_queue_t* pqt = (timer_queue_t*)rq;
	timer_token_t* ptt = (timer_token_t*)rt;
	int i;

	if(!rq) return;

	if(!rt) return;

	for(i = 0;i<MAX_TIMER_LISTEN;i++)
	{
		if(ptt->queue == pqt->tt[i].queue)
		{
			pqt->tt[i].active = 0;
			_event_wait(pqt->tt[i].ev, -1);
			_event_destroy(pqt->tt[i].ev);

			close(pqt->tt[i].queue);
			pqt->tt[i].queue = 0;
			pqt->tt[i].pf = NULL;
			pqt->tt[i].pa = NULL;

			break;
		}
	}
}

bool_t _alter_timer(res_queue_t rq, res_timer_t rt, dword_t duetime, dword_t period)
{
	timer_token_t* ptt = (timer_token_t*)rt;

	if(!rt) return 0;

	ptt->due.tv_sec = duetime / 1000;
	ptt->due.tv_nsec = (duetime % 1000 ) * 1000000;
	ptt->per.tv_sec = period / 1000;
	ptt->per.tv_nsec = (period % 1000 ) * 1000000;

	return (bool_t)1;
}

#endif //XDK_SUPPORT_TIMER
