﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc tcp service document

	@module	srvtcp.c | implement file

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

#include "srvtcp.h"

#include "../xdknet.h"
#include "../xdkimp.h"
#include "../xdkoem.h"
#include "../xdkstd.h"

typedef struct _tcp_accept_t{
	res_file_t so;

	res_even_t ev;

	NET_SECU secu;
	void* pf_param;
	union
	{
		PF_TCPS_DISPATCH pf_dispatch;
		const tchar_t* sz_module;
	};
}tcp_accept_t;

/************************************************************************************************/
static tcp_listen_t*  _xtcp_listen(unsigned short port)
{
	tcp_listen_t* plis;
	net_addr_t sin;
	res_file_t so;
	sys_info_t si = { 0 };
	
	so = socket_tcp(0, FILE_OPEN_OVERLAP);
	if (so == INVALID_FILE)
	{
		return NULL;
	}

	xmem_zero((void*)&sin, sizeof(sin));

	fill_addr(&sin, port, NULL);

	if (!socket_bind(so, (res_addr_t)&sin, sizeof(sin)))
	{
		socket_close(so);
		return NULL; //bind sock error
	}

	if (!socket_listen(so, SOMAXCONN))
	{
		socket_close(so);
		return NULL; //listen error
	}

	plis = (tcp_listen_t*)xmem_alloc(sizeof(tcp_listen_t));

	plis->so = so;
	plis->act = 1;
	plis->cri = criti_create();

	system_info(&si);
	plis->res = si.processor_number;

	return plis;
}

static unsigned STDCALL thread_dispatch(void* param)
{
	tcp_accept_t* pxa = (tcp_accept_t*)param;

	PF_TCPS_DISPATCH pf_dispatch = NULL;
	void* pf_param = NULL;
	int secu;
	xhand_t bio = NULL;
	res_file_t so = 0;
	res_even_t ev = NULL;

	xdk_thread_init(0);

	so = pxa->so;
	pxa->so = 0;
	pf_dispatch = pxa->pf_dispatch;
	secu = pxa->secu;
	pf_param = pxa->pf_param;
	ev = pxa->ev;

	event_sign(ev, 1);
    
	switch (secu)
	{
	case _SECU_SSL:
		bio = xssl_srv(so);
		break;
	case _SECU_SSH:
		bio = xssh_srv(so);
		break;
	default:
		bio = xtcp_srv(so);
		break;
	}

	if (bio && pf_dispatch)
	{
		(*pf_dispatch)(bio, pf_param);
	}

	switch (secu)
	{
	case _SECU_SSL:
		if (bio) xssl_close(bio);
		break;
	case _SECU_SSH:
		if (bio) xssh_close(bio);
		break;
	default:
		if (bio) xtcp_close(bio);
		break;
	}

	socket_shutdown(so, 2);

	thread_yield();

	socket_close(so);

	xdk_thread_uninit(0);

	thread_stop();

	return 0;
}

static unsigned STDCALL process_dispatch(void* param)
{
	tcp_accept_t* pxa = (tcp_accept_t*)param;

	res_file_t so;
	const tchar_t* sz_module = NULL;
	const tchar_t* sz_param = NULL;
	res_even_t ev;

	proc_info_t pi = { 0 };

	xdk_thread_init(0);

	so = pxa->so;
	pxa->so = 0;
	sz_module = pxa->sz_module;
	sz_param = (const tchar_t*)pxa->pf_param;
	ev = pxa->ev;

	event_sign(ev, 1);

	if (create_process(sz_module, (tchar_t*)sz_param, SHARE_SOCK, &pi))
	{
		socket_share(pi.process_id, pi.pip_write, so, NULL, 0);

        thread_yield();
        
        release_process(&pi);
	}
	else
	{
		thread_yield();
	}

	socket_close(so);

	xdk_thread_uninit(0);

	thread_stop();

	return 0;
}

static unsigned STDCALL wait_accept(void* param)
{
	tcp_listen_t* plis = (tcp_listen_t*)param;

	res_file_t so;
	net_addr_t locaddr, rmtaddr;
	int addr_len;
	tcp_accept_t xa = { 0 };
	async_t asy = { 0 };

	xdk_thread_init(0);

	if (plis->res == 1)
	{
		async_init(&asy, ASYNC_QUEUE, TCP_BASE_TIMO, plis->so);
	}
	else
	{
		async_init(&asy, ASYNC_EVENT, TCP_BASE_TIMO, INVALID_FILE);
	}

	socket_addr(plis->so, &locaddr);

	while (plis->act)
	{
		addr_len = sizeof(net_addr_t);

		if (plis->cri)
		{
			criti_enter(plis->cri);
		}

		so = socket_accept(plis->so, (res_addr_t)&rmtaddr, &addr_len, &asy);

		if (plis->cri)
		{
			criti_leave(plis->cri);
		}

		if (so == INVALID_FILE)
		{
			thread_yield();
			continue;
		}

		xa.so = so;
		xa.secu = plis->secu;
		xa.pf_param = plis->pf_param;
		if (plis->is_thread)
			xa.pf_dispatch = plis->pf_dispatch;
		else
			xa.sz_module = plis->sz_module;

		xa.pf_param = plis->pf_param;
		xa.ev = event_create();
		if (xa.ev)
		{
			if (plis->is_thread)
			{
				thread_start(NULL, (PF_THREADFUNC)thread_dispatch, (void*)&xa);
			}
			else
			{
				thread_start(NULL, (PF_THREADFUNC)process_dispatch, (void*)&xa);
			}

			event_wait(xa.ev, TCP_BASE_TIMO);
			event_destroy(xa.ev);
		}

		if (xa.so)
		{
			socket_close(xa.so);
		}

		xmem_zero((void*)&xa, sizeof(tcp_accept_t));
	}

	async_uninit(&asy);

	xdk_thread_uninit(0);

	thread_stop();

	return 0;
}

tcp_listen_t* xtcp_start_thread(unsigned short port, NET_SECU secu, PF_TCPS_DISPATCH pf_dispatch, void* param)
{
	tcp_listen_t* plis;
	int i;

	plis = _xtcp_listen(port);
	if (!plis)
		return NULL;

	plis->secu = secu;
	plis->is_thread = 1;
	plis->pf_dispatch = pf_dispatch;
	plis->pf_param = param;

	plis->thr = (res_thread_t*)xmem_alloc(sizeof(res_thread_t) * plis->res);

	for (i = 0; i < plis->res; i++)
	{
		thread_start(&(plis->thr[i]), (PF_THREADFUNC)wait_accept, (void*)plis);
	}

	return plis;
}

tcp_listen_t* xtcp_start_process(unsigned short port, NET_SECU secu, const tchar_t* sz_module, tchar_t* sz_cmdline)
{
	tcp_listen_t* plis;
	int i;

	plis = _xtcp_listen(port);
	if (!plis)
		return NULL;

	plis->secu = secu;
	plis->is_thread = 0;
	plis->sz_module = sz_module;
	plis->pf_param = (void*)sz_cmdline;

	plis->thr = (res_thread_t*)xmem_alloc(sizeof(res_thread_t) * plis->res);

	for (i = 0; i < plis->res; i++)
	{
		thread_start(&(plis->thr[i]), (PF_THREADFUNC)wait_accept, (void*)plis);
	}

	return plis;
}

void xtcp_stop(tcp_listen_t* plis)
{
	int i;
	//indicate listen to be stoping
	plis->act = 0;

	//disiable recive and send
	socket_shutdown(plis->so, 2);

	thread_yield();

	socket_close(plis->so);

	for (i = 0; i < plis->res; i++)
	{
		if (plis->thr[i])
		{
			thread_join(plis->thr[i]);
		}
	}

	if (plis->cri)
		criti_destroy(plis->cri);

	xmem_free(plis->thr);

	xmem_free(plis);
}


