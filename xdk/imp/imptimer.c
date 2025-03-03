﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc timer document

	@module	imptimer.c | implement file

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

#include "imptimer.h"

#include "../xdkimp.h"
#include "../xdkstd.h"

#ifdef XDK_SUPPORT_TIMER

res_queue_t create_timer_queue(void)
{
	if_timer_t* pif;

	pif = PROCESS_TIMER_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_create_timer_queue)();
}

void destroy_timer_queue(res_queue_t rq)
{
	if_timer_t* pif;

	pif = PROCESS_TIMER_INTERFACE;

	XDK_ASSERT(pif != NULL);

	(*pif->pf_destroy_timer_queue)(rq);
}

res_timer_t create_timer(res_queue_t rq, dword_t duetime, dword_t period, PF_TIMERFUNC pf, void* pa)
{
	if_timer_t* pif;

	pif = PROCESS_TIMER_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_create_timer)(rq, duetime, period, pf, pa);
}

void destroy_timer(res_queue_t rq, res_timer_t rt)
{
	if_timer_t* pif;

	pif = PROCESS_TIMER_INTERFACE;

	XDK_ASSERT(pif != NULL);

	(*pif->pf_destroy_timer)(rq, rt);
}

bool_t alter_timer(res_queue_t rq, res_timer_t rt, dword_t duetime, dword_t period)
{
	if_timer_t* pif;

	pif = PROCESS_TIMER_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_alter_timer)(rq, rt, duetime, period);
}

#endif /*XDK_SUPPORT_TIMER*/
