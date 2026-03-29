/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc initialize document

	@module	xdkinit.c | implement file

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


#include "xdkinit.h"

#include "xdkstd.h"
#include "xdkimp.h"
#include "xdkloc.h"

//xdk_mou_t g_xdk_mou = { 0 };

xdk_mou_t g_xdk_mou = {
	.if_ok = bool_false,
	.if_opt = 0,
	.if_big = 0,

#ifdef XDK_SUPPORT_THREAD
		.thread_id = 0,
		.tls_thr_zero = 0,
		.tls_thr_zone = 0,
		.tls_thr_jump = 0,
		.tls_thr_dump = 0,
#else
		.pif_zone = NULL,
		.pif_jump = NULL,
		.pif_dump = NULL,
#endif //XDK_SUPPORT_THREAD

#ifdef XDK_SUPPORT_MEMO
	.if_memo.pf_local_alloc = _local_alloc,
	.if_memo.pf_local_alloc = _local_alloc,
	.if_memo.pf_local_realloc = _local_realloc,
	.if_memo.pf_local_free = _local_free,

#ifdef XDK_SUPPORT_MEMO_HEAP
	.if_memo.pf_process_heap = _process_heapo,
	.if_memo.pf_heap_create = _heapo_create,
	.if_memo.pf_heap_destroy = _heapo_destroy,
	.if_memo.pf_heap_clean = _heapo_clean,
	.if_memo.pf_heap_alloc = _heapo_alloc,
	.if_memo.pf_heap_realloc = _heapo_realloc,
	.if_memo.pf_heap_free = _heapo_free,
	.if_memo.pf_heap_zero = _heapo_zero,
#endif

#ifdef XDK_SUPPORT_MEMO_PAGE
	.if_memo.pf_page_alloc = _paged_alloc,
	.if_memo.pf_page_realloc = _paged_realloc,
	.if_memo.pf_page_free = _paged_free,
	.if_memo.pf_page_lock = _paged_lock,
	.if_memo.pf_page_size = _paged_size,
	.if_memo.pf_page_unlock = _paged_unlock,
#endif

#ifdef XDK_SUPPORT_MEMO_CACHE
	.if_memo.pf_cache_open = _cache_open,
	.if_memo.pf_cache_close = _cache_close,
	.if_memo.pf_cache_write = _cache_write,
	.if_memo.pf_cache_read = _cache_read,
	.if_memo.pf_cache_protect = _cache_protect,
#endif
#endif //XDK_SUPPORT_MEMO

#ifdef XDK_SUPPORT_ERROR
	.if_error.pf_error_text = _error_text,
	.if_error.pf_error_exit = _error_exit,
	.if_error.pf_error_debug = _error_debug,
	.if_error.pf_error_print = _error_print,
#endif //XDK_SUPPORT_ERROR

#ifdef XDK_SUPPORT_MBCS
	.if_mbcs.pf_utf_to_ucs = c_utf_to_ucs,
	.if_mbcs.pf_ucs_to_utf = c_ucs_to_utf,
	.if_mbcs.pf_gbk_to_ucs = c_gbk_to_ucs,
	.if_mbcs.pf_ucs_to_gbk = c_ucs_to_gbk,
#endif //XDK_SUPPORT_MBCS

#ifdef XDK_SUPPORT_ASYNC
	.if_async.pf_async_init = _async_init,
	.if_async.pf_async_uninit = _async_uninit,
#endif //XDK_SUPPORT_ASYNC

#ifdef XDK_SUPPORT_DATE
	.if_date.pf_get_loc_date = _get_loc_date,
	.if_date.pf_get_utc_date = _get_utc_date,
	.if_date.pf_mak_loc_week = _mak_loc_week,
	.if_date.pf_mak_utc_week = _mak_utc_week,
	.if_date.pf_loc_date_to_utc = _loc_date_to_utc,
	.if_date.pf_utc_date_to_loc = _utc_date_to_loc,
	.if_date.pf_get_times = _get_times,
	.if_date.pf_get_ticks = _get_ticks,
	.if_date.pf_get_timestamp = _get_timestamp,
	.if_date.pf_utc_date_from_times = _utc_date_from_times,
	.if_date.pf_utc_date_from_ticks = _utc_date_from_ticks,
	.if_date.pf_utc_date_from_timestamp = _utc_date_from_timestamp,
#endif //XDK_SUPPORT_DATE

#ifdef XDK_SUPPORT_THREAD
	.if_thread.pf_thread_begin = _thread_begin,
	.if_thread.pf_thread_end = _thread_end,
	.if_thread.pf_thread_sleep = _thread_sleep,
	.if_thread.pf_thread_yield = _thread_yield,
	.if_thread.pf_thread_get_id = _thread_get_id,
	.if_thread.pf_thread_create_tls = _thread_create_tls,
	.if_thread.pf_thread_destroy_tls = _thread_destroy_tls,
	.if_thread.pf_thread_get_tls = _thread_get_tls,
	.if_thread.pf_thread_set_tls = _thread_set_tls,
	.if_thread.pf_thread_join = _thread_join,
    .if_thread.pf_thread_safe = _thread_safe,
#ifdef XDK_SUPPORT_THREAD_EVENT
	.if_thread.pf_event_create = _event_create,
	.if_thread.pf_event_destroy = _event_destroy,
	.if_thread.pf_event_sign = _event_sign,
	.if_thread.pf_event_wait = _event_wait,
#endif
#ifdef XDK_SUPPORT_THREAD_CRITI
	.if_thread.pf_criti_create = _criti_create,
	.if_thread.pf_criti_destroy = _criti_destroy,
	.if_thread.pf_criti_enter = _criti_enter,
	.if_thread.pf_criti_leave = _criti_leave,
	.if_thread.pf_criti_query = _criti_query,
#endif
#ifdef XDK_SUPPORT_THREAD_MUTEX
	.if_thread.pf_mutex_create = _mutex_create,
	.if_thread.pf_mutex_destroy = _mutex_destroy,
	.if_thread.pf_mutex_open = _mutex_open,
	.if_thread.pf_mutex_close = _mutex_close,
	.if_thread.pf_mutex_lock = _mutex_lock,
	.if_thread.pf_mutex_unlock = _mutex_unlock,
#endif
#ifdef XDK_SUPPORT_THREAD_SEMAP
	.if_thread.pf_semap_create = _semap_create,
	.if_thread.pf_semap_destroy = _semap_destroy,
	.if_thread.pf_semap_open = _semap_open,
	.if_thread.pf_semap_close = _semap_close,
	.if_thread.pf_semap_lock = _semap_lock,
	.if_thread.pf_semap_unlock = _semap_unlock,
#endif
#ifdef XDK_SUPPORT_THREAD_QUEUE
	.if_thread.pf_queue_create = _queue_create,
	.if_thread.pf_queue_destroy = _queue_destroy,
	.if_thread.pf_queue_wait = _queue_wait,
#endif
#endif //XDK_SUPPORT_THREAD

#ifdef XDK_SUPPORT_TIMER
	.if_timer.pf_create_timer_queue = _create_timer_queue,
	.if_timer.pf_destroy_timer_queue = _destroy_timer_queue,
	.if_timer.pf_create_timer = _create_timer,
	.if_timer.pf_destroy_timer = _destroy_timer,
	.if_timer.pf_alter_timer = _alter_timer,
#endif //XDK_SUPPORT_TIMER

#ifdef XDK_SUPPORT_RANDOM
	.if_random.pf_system_srand = _system_srand,
	.if_random.pf_system_rand32 = _system_rand32,
	.if_random.pf_system_rand64 = _system_rand64,
#endif //XDK_SUPPORT_RANDOM

#ifdef XDK_SUPPORT_SOCK
	.if_socket.pf_socket_startup = _socket_startup,
	.if_socket.pf_socket_cleanup = _socket_cleanup,
	.if_socket.pf_socket_tcp = _socket_tcp,
	.if_socket.pf_socket_udp = _socket_udp,
	.if_socket.pf_socket_icmp = _socket_icmp,
	.if_socket.pf_socket_close = _socket_close,
	.if_socket.pf_socket_wait = _socket_wait,
	.if_socket.pf_socket_shutdown = _socket_shutdown,
	.if_socket.pf_socket_connect = _socket_connect,
	.if_socket.pf_socket_bind = _socket_bind,
	.if_socket.pf_socket_sendto = _socket_sendto,
	.if_socket.pf_socket_recvfrom = _socket_recvfrom,
	.if_socket.pf_socket_recv = _socket_recv,
	.if_socket.pf_socket_send = _socket_send,
	.if_socket.pf_socket_setopt = _socket_setopt,
	.if_socket.pf_socket_getopt = _socket_getopt,
	.if_socket.pf_socket_set_linger = _socket_set_linger,
	.if_socket.pf_socket_set_sndbuf = _socket_set_sndbuf,
	.if_socket.pf_socket_set_rcvbuf = _socket_set_rcvbuf,
	.if_socket.pf_socket_set_nonblk = _socket_set_nonblk,
	.if_socket.pf_socket_get_nonblk = _socket_get_nonblk,
	.if_socket.pf_fill_addr = _fill_addr,
	.if_socket.pf_conv_addr = _conv_addr,
	.if_socket.pf_host_addr = _host_addr,
	.if_socket.pf_socket_peer = _socket_peer,
	.if_socket.pf_socket_addr = _socket_addr,
	.if_socket.pf_socket_accept = _socket_accept,
	.if_socket.pf_socket_listen = _socket_listen,
	.if_socket.pf_socket_dupli = _socket_dupli,
	.if_socket.pf_socket_share = _socket_share,
	.if_socket.pf_socket_write = _socket_write,
	.if_socket.pf_socket_read = _socket_read,
	.if_socket.pf_socket_error = _socket_error,
#endif //XDK_SUPPORT_SOCK

#ifdef XDK_SUPPORT_PIPE
	.if_pipe.pf_pipe_srv = _pipe_srv,
	.if_pipe.pf_pipe_listen = _pipe_listen,
	.if_pipe.pf_pipe_stop = _pipe_stop,
	.if_pipe.pf_pipe_cli = _pipe_cli,
	.if_pipe.pf_pipe_close = _pipe_close,
	.if_pipe.pf_pipe_wait = _pipe_wait,
	.if_pipe.pf_pipe_read = _pipe_read,
	.if_pipe.pf_pipe_write = _pipe_write,
	.if_pipe.pf_pipe_flush = _pipe_flush,
#endif //XDK_SUPPORT_PIPE

#ifdef XDK_SUPPORT_SHARE
	.if_share.pf_share_srv = _share_srv,
	.if_share.pf_share_cli = _share_cli,
	.if_share.pf_share_close = _share_close,
	.if_share.pf_share_write = _share_write,
	.if_share.pf_share_read = _share_read,
	.if_share.pf_share_lock = _share_lock,
	.if_share.pf_share_unlock = _share_unlock,
#endif //XDK_SUPPORT_SHARE

#ifdef XDK_SUPPORT_FILE
	.if_file.pf_file_open = _file_open,
	.if_file.pf_file_close = _file_close,
	.if_file.pf_file_size = _file_size,
	.if_file.pf_file_read = _file_read,
	.if_file.pf_file_read_range = _file_read_range,
	.if_file.pf_file_write_range = _file_write_range,
	.if_file.pf_file_lock_range = _file_lock_range,
	.if_file.pf_file_unlock_range = _file_unlock_range,
	.if_file.pf_file_write = _file_write,
	.if_file.pf_file_flush = _file_flush,
	.if_file.pf_file_truncate = _file_truncate,
	.if_file.pf_file_seek_begin = _file_seek_begin,
	.if_file.pf_file_seek_end = _file_seek_end,
	.if_file.pf_file_seek_bytes = _file_seek_bytes,
	.if_file.pf_file_seek_lines = _file_seek_lines,
	.if_file.pf_file_peek_line = _file_peek_line,
	.if_file.pf_file_read_line = _file_read_line,
	.if_file.pf_file_write_line = _file_write_line,
	.if_file.pf_file_delete = _file_delete,
	.if_file.pf_file_rename = _file_rename,
	.if_file.pf_file_info = _file_info,
	.if_file.pf_directory_open = _directory_open,
	.if_file.pf_file_settime = _file_settime,
	.if_file.pf_file_gettime = _file_gettime,
#ifdef XDK_SUPPORT_FILE_FIND
	.if_file.pf_file_find_first = _file_find_first,
	.if_file.pf_file_find_next = _file_find_next,
	.if_file.pf_file_find_close = _file_find_close,
#endif
#endif //XDK_SUPPORT_FILE

#ifdef XDK_SUPPORT_COMM
	.if_comm.pf_default_comm_mode = _default_comm_mode,
	.if_comm.pf_set_comm_mode = _set_comm_mode,
	.if_comm.pf_get_comm_mode = _get_comm_mode,
	.if_comm.pf_comm_listen = _comm_listen,
	.if_comm.pf_comm_open = _comm_open,
	.if_comm.pf_comm_close = _comm_close,
	.if_comm.pf_comm_read = _comm_read,
	.if_comm.pf_comm_write = _comm_write,
	.if_comm.pf_comm_flush = _comm_flush,
#endif //XDK_SUPPORT_COMM

#ifdef XDK_SUPPORT_CONS
	.if_cons.pf_cons_alloc = _cons_alloc,
	.if_cons.pf_cons_free = _cons_free,
	.if_cons.pf_cons_sigaction = _cons_sigaction,
	.if_cons.pf_cons_read = _cons_read,
	.if_cons.pf_cons_write = _cons_write,
	.if_cons.pf_cons_flush = _cons_flush,
	.if_cons.pf_cons_stdin = _cons_stdin,
	.if_cons.pf_cons_stdout = _cons_stdout,
#endif //XDK_SUPPORT_CONS

#ifdef XDK_SUPPORT_PROCESS
	.if_process.pf_free_library = _free_library,
	.if_process.pf_get_address = _get_address,
	.if_process.pf_load_library = _load_library,
	.if_process.pf_get_curpath = _get_curpath,
	.if_process.pf_get_runpath = _get_runpath,
	.if_process.pf_create_process = _create_process,
	.if_process.pf_release_process = _release_process,
	.if_process.pf_process_wait_run = _process_wait_run,
	.if_process.pf_process_wait_exit = _process_wait_exit,
    .if_process.pf_process_safe = _process_safe,
	.if_process.pf_process_dupli = _process_dupli,
	.if_process.pf_process_alloc = _process_alloc,
	.if_process.pf_process_free = _process_free,
	.if_process.pf_process_write = _process_write,
	.if_process.pf_process_read = _process_read,
	.if_process.pf_release_handle = _release_handle,
	.if_process.pf_inherit_handle = _inherit_handle,
	.if_process.pf_read_profile = _read_profile,
	.if_process.pf_write_profile = _write_profile,
	.if_process.pf_get_envvar = _get_envvar,
	.if_process.pf_system_info = _system_info,
#endif //XDK_SUPPORT_PROCESS

#ifdef XDK_SUPPORT_MEMO_DUMP
		.dump_crit = 0,
		.dump_link = {0}
#endif //XDK_SUPPORT_MEMO_DUMP
};


jmp_buf* thread_jump_buff(void)
{
	if_jump_t* pju;

	pju = THREAD_JUMP_INTERFACE;
	if (!pju)
		return NULL;

	return &(pju->if_buf[pju->if_index]);
}

#ifdef XDK_SUPPORT_THREAD

static void _action_pipe(int sig)
{
    NOP;
}

void xdk_thread_init(int master)
{
	if_zone_t* pzn;
	if_jump_t* pju;
	if_dump_t* pdu;

	if_memo_t* piv;
	if_thread_t* pit;
#ifdef XDK_SUPPORT_MEMO_HEAP
	void* heap = NULL;
#endif
    dword_t tid;

    XDK_ASSERT(XDK_MOUNTED);

	piv = PROCESS_MEMO_INTERFACE;
	pit = PROCESS_THREAD_INTERFACE;

    if(!master)
    {
        (*pit->pf_thread_safe)();
    }
    
    tid = (*pit->pf_thread_get_id)();

#ifdef XDK_SUPPORT_MEMO_HEAP  
	if (g_xdk_mou.if_opt & XDK_APARTMENT_THREAD)
	{
		heap = (*piv->pf_heap_create)();
	}
	else
	{
		heap = (*piv->pf_process_heap)();
	}
	
	XDK_ASSERT(heap != NULL);

	pzn = (if_zone_t*)(*piv->pf_heap_alloc)(heap, sizeof(if_zone_t));
#else
	pzn = (if_zone_t*)(*piv->pf_local_alloc)(sizeof(if_zone_t));
#endif /*XDK_SUPPORT_MEMO_HEAP*/

#ifdef XDK_SUPPORT_MEMO_HEAP 
	pzn->if_heap = heap;
#endif

	XDK_ASSERT(g_xdk_mou.tls_thr_zone != 0);
	(*pit->pf_thread_set_tls)(g_xdk_mou.tls_thr_zone, (void*)pzn);
#ifdef XDK_SUPPORT_MEMO_DUMP
	init_root_link(&pzn->if_hand);
	init_root_link(&pzn->if_dump);

	(*pit->pf_criti_enter)(g_xdk_mou.dump_crit);

	pzn->if_trak.tag = (int)(*pit->pf_thread_get_id)();
	pzn->if_trak.next = pzn->if_trak.prev = NULL;
	insert_link_after(&g_xdk_mou.dump_link, LINK_LAST, &pzn->if_trak);

	(*pit->pf_criti_leave)(g_xdk_mou.dump_crit);
#endif
#ifdef XDK_SUPPORT_MEMO_HEAP
	pju = (if_jump_t*)(*piv->pf_heap_alloc)(heap, sizeof(if_jump_t));
	pdu = (if_dump_t*)(*piv->pf_heap_alloc)(heap, sizeof(if_dump_t));
#else
	pju = (if_jump_t*)(*piv->pf_local_alloc)(sizeof(if_jump_t));
	pdu = (if_dump_t*)(*piv->pf_local_alloc)(sizeof(if_dump_t));
#endif

	pju->if_buf = NULL;
	pju->if_index = -1;
	pju->if_size = 0;

	pdu->err_enable = 1;

	XDK_ASSERT(g_xdk_mou.tls_thr_jump != 0);
	(*pit->pf_thread_set_tls)(g_xdk_mou.tls_thr_jump, (void*)pju);

	XDK_ASSERT(g_xdk_mou.tls_thr_dump != 0);
	(*pit->pf_thread_set_tls)(g_xdk_mou.tls_thr_dump, (void*)pdu);
}

void xdk_thread_uninit(int error)
{
	if_zone_t* pzn;
	if_jump_t* pju;
	if_dump_t* pdu;
	err_dump_t* per;
	if_memo_t* piv;
	if_thread_t* pit;
#ifdef XDK_SUPPORT_MEMO_HEAP
	void* heap = NULL;
#endif

	if (!error)
	{
		XDK_ASSERT(XDK_MOUNTED);
	}

	if (!XDK_MOUNTED)
		return;

	piv = PROCESS_MEMO_INTERFACE;
	pit = PROCESS_THREAD_INTERFACE;

	if (!error)
	{
		XDK_ASSERT(g_xdk_mou.tls_thr_zone != 0);
	}

	if (!g_xdk_mou.tls_thr_zone)
		return;

	pzn = (if_zone_t*)(*pit->pf_thread_get_tls)(g_xdk_mou.tls_thr_zone);
	
	if (!error)
	{
		XDK_ASSERT(pzn != NULL);
	}

	if (!pzn)
		return;

#ifdef XDK_SUPPORT_MEMO_HEAP
	heap = pzn->if_heap;

	if (!error)
	{
		XDK_ASSERT(heap != NULL);
	}

	if (!heap)
		return;
#endif /*XDK_SUPPORT_MEMO_HEAP*/

	if (g_xdk_mou.tls_thr_dump != 0)
	{
		pdu = (if_dump_t*)(*pit->pf_thread_get_tls)(g_xdk_mou.tls_thr_dump);
		while (pdu && pdu->err_dump)
		{
			pdu->err_enable = 0;

			per = pdu->err_dump;
			pdu->err_dump = per->err_next;

#ifdef XDK_SUPPORT_MEMO_HEAP
			(*piv->pf_heap_free)(heap, per->err_code);
			(*piv->pf_heap_free)(heap, per->err_text);
			(*piv->pf_heap_free)(heap, per);
#else
			(*piv->pf_local_free)(per->err_code);
			(*piv->pf_local_free)(per->err_text);
			(*piv->pf_local_free)(per);
#endif
		}
#ifdef XDK_SUPPORT_MEMO_HEAP
		if (pdu)
			(*piv->pf_heap_free)(heap, (void*)pdu);
#else
		if (pdu)
			(*piv->pf_local_free)((void*)pdu);
#endif

		(*pit->pf_thread_set_tls)(g_xdk_mou.tls_thr_dump, 0);
	}

	if (g_xdk_mou.tls_thr_jump != 0)
	{
		pju = (if_jump_t*)(*pit->pf_thread_get_tls)(g_xdk_mou.tls_thr_jump);

		if (!error)
		{
			XDK_ASSERT(pju->if_buf == NULL);
		}

		if (pju)
		{
			clear_jump();
		}

#ifdef XDK_SUPPORT_MEMO_HEAP
		if(pju)
			(*piv->pf_heap_free)(heap, (void*)pju);
#else
		if(pju)
			(*piv->pf_local_free)((void*)pju);
#endif

		(*pit->pf_thread_set_tls)(g_xdk_mou.tls_thr_jump, 0);
	}

#ifdef XDK_SUPPORT_MEMO_DUMP
	(*pit->pf_criti_enter)(g_xdk_mou.dump_crit);

	if (!error)
	{
		xmem_dump();
	}

	delete_link(&g_xdk_mou.dump_link, &pzn->if_trak);

	(*pit->pf_criti_leave)(g_xdk_mou.dump_crit);
#endif

#ifdef XDK_SUPPORT_MEMO_HEAP
	(*piv->pf_heap_free)(heap, (void*)pzn);

	if (g_xdk_mou.if_opt & XDK_APARTMENT_THREAD)
		(*piv->pf_heap_destroy)(heap);
	else
		(*piv->pf_heap_clean)(heap);
		
#else 
	(*piv->pf_local_free)((void*)pzn);
#endif //XDK_SUPPORT_MEMO_HEAP

	(*pit->pf_thread_set_tls)(g_xdk_mou.tls_thr_zone, 0);
}

#endif //XDK_SUPPORT_THREAD

static int _is_big_endian()
{
	union cu
	{
		int i;
		char j;
	} n;

	n.i = 1;

	return (n.j == 1) ? 0 : 1;
}

//mount system call
void xdk_process_init(dword_t opt)
{
#if defined(XDK_SUPPORT_PROCESS)
    if_process_t* pro;
#endif
#if defined(XDK_SUPPORT_THREAD)
	if_thread_t* pit;
#endif

#ifdef XDK_SUPPORT_MEMO_HEAP
	void* heap = NULL;
#endif

	if (g_xdk_mou.if_ok)
		return;

    g_xdk_mou.if_ok = 1;
	g_xdk_mou.if_opt = opt;

	g_xdk_mou.if_big = _is_big_endian();
    
#ifdef XDK_SUPPORT_PROCESS
    pro = PROCESS_PROCESS_INTERFACE;
    (*pro->pf_process_safe)();
#endif

#ifdef XDK_SUPPORT_THREAD
	pit = PROCESS_THREAD_INTERFACE;
	g_xdk_mou.thread_id = (*pit->pf_thread_get_id)();

	//create thread id, heap, jump local storage index
	(*pit->pf_thread_create_tls)(&g_xdk_mou.tls_thr_zero);
	(*pit->pf_thread_create_tls)(&g_xdk_mou.tls_thr_zone);
	(*pit->pf_thread_create_tls)(&g_xdk_mou.tls_thr_jump);
	(*pit->pf_thread_create_tls)(&g_xdk_mou.tls_thr_dump);
#else
	pim = PROCESS_MEMO_INTERFACE;

#ifdef XDK_SUPPORT_MEMO_HEAP
	heap = (*pim->pf_process_heap)();

	g_xdk_mou.pif_zone = (if_zone_t*)(*pim->pf_heap_alloc)(heap, sizeof(if_zone_t));
	g_xdk_mou.pif_zone->if_heap = heap;

	g_xdk_mou.pif_jump = (if_jump_t*)(*pim->pf_heap_alloc)(heap, sizeof(if_jump_t));
	g_xdk_mou.pif_dump = (if_dump_t*)(*pim->pf_heap_alloc)(heap, sizeof(if_dump_t));
#else
	g_xdk_mou.pif_zone = (if_zone_t*)(*pim->pf_local_alloc)(sizeof(if_heap_t));

	g_xdk_mou.pif_jump = (if_jump_t*)(*pim->pf_local_alloc)(sizeof(if_jump_t));
	g_xdk_mou.pif_dump = (if_dump_t*)(*pim->pf_local_alloc)(sizeof(if_dump_t));
#endif //XDK_SUPPORT_MEMO_HEAP

	g_xdk_mou.pif_jump->if_buf = NULL;
	g_xdk_mou.pif_jump->if_index = -1;
	g_xdk_mou.pif_jump->if_size = 0;

#endif //XDK_SUPPORT_TRHEAD

#if defined(XDK_SUPPORT_MEMO_DUMP) && defined(XDK_SUPPORT_THREAD)
	pit = PROCESS_THREAD_INTERFACE;
	g_xdk_mou.dump_crit = (*pit->pf_criti_create)();
	init_root_link(&g_xdk_mou.dump_link);
#endif

#ifdef XDK_SUPPORT_THREAD
	//init the master thread local heap, error handler
	xdk_thread_init(1);
#endif
    
#ifdef XDK_SUPPORT_SOCK
	if (g_xdk_mou.if_socket.pf_socket_startup)
	{
		(*g_xdk_mou.if_socket.pf_socket_startup)();
	}
#endif

#ifdef XDK_SUPPORT_ACP
	share_acp_init();
#endif
}

//unmount system call
void xdk_process_uninit()
{
#ifdef XDK_SUPPORT_THREAD
	if_thread_t* pit;
#endif

	if (!g_xdk_mou.if_ok)
		return;

#ifdef XDK_SUPPORT_ACP
	share_acp_uninit();
#endif

#ifdef XDK_SUPPORT_SOCK
	(*g_xdk_mou.if_socket.pf_socket_cleanup)();
#endif

#ifdef XDK_SUPPORT_THREAD
	pit = PROCESS_THREAD_INTERFACE;

	//uninit the master thread local heap, error handler
	xdk_thread_uninit(0);

	//destroy thread id, heap, jump local storage index
	(*pit->pf_thread_destroy_tls)(g_xdk_mou.tls_thr_zero);
	g_xdk_mou.tls_thr_zero = 0;
	(*pit->pf_thread_destroy_tls)(g_xdk_mou.tls_thr_zone);
	g_xdk_mou.tls_thr_zone = 0;
	(*pit->pf_thread_destroy_tls)(g_xdk_mou.tls_thr_jump);
	g_xdk_mou.tls_thr_jump = 0;
	(*pit->pf_thread_destroy_tls)(g_xdk_mou.tls_thr_dump);
	g_xdk_mou.tls_thr_dump = 0;
#ifdef XDK_SUPPORT_MEMO_DUMP
	(*pit->pf_criti_enter)(g_xdk_mou.dump_crit);

	thread_dump();

	(*pit->pf_criti_leave)(g_xdk_mou.dump_crit);

	(*pit->pf_criti_destroy)(g_xdk_mou.dump_crit);
#endif

#else

	pim = PROCESS_MEMO_INTERFACE;

#ifdef XDK_SUPPORT_MEMO_HEAP
	(*pim->pf_heap_free)(g_xdk_mou.pif_zone->if_heap, g_xdk_mou.pif_dump);
	g_xdk_mou.pif_dump = NULL;
	(*pim->pf_heap_free)(g_xdk_mou.pif_zone->if_heap, g_xdk_mou.pif_jump);
	g_xdk_mou.pif_jump = NULL;
	(*pim->pf_heap_free)(g_xdk_mou.pif_zone->if_heap, g_xdk_mou.pif_zone);
	g_xdk_mou.pif_zone = NULL;
#else
	(*pim->pf_local_free)(g_xdk_mou.pif_dump);
	g_xdk_mou.pif_dump = NULL;
	(*pim->pf_local_free)(g_xdk_mou.pif_jump);
	g_xdk_mou.pif_jump = NULL;
	(*pim->pf_local_free)(g_xdk_mou.pif_zone);
	g_xdk_mou.pif_heap = NULL;
#endif //XDK_SUPPORT_MEMO_HEAP

#endif //XDK_SUPPORT_THREAD

	g_xdk_mou.if_ok = bool_false;
	g_xdk_mou.if_opt = 0;
}

#ifdef XDK_SUPPORT_MEMO_HEAP
void xdk_process_clean()
{
	if_memo_t* piv;
	res_heap_t heap;

	piv = PROCESS_MEMO_INTERFACE;

	XDK_ASSERT(piv != NULL);

	heap = (*piv->pf_process_heap)();
	(*piv->pf_heap_clean)(heap);
}
#else
void xdk_process_clean()
{
	return;
}
#endif //XDK_SUPPORT_MEMO_HEAP


#if defined(XDK_SUPPORT_MEMO_DUMP) && defined(XDK_SUPPORT_THREAD)

void thread_dump()
{
	link_t_ptr plk, nlk;
	tchar_t token[ERR_LEN + 1];
	dword_t dw;

	if_error_t* pie;
#ifdef XDK_SUPPORT_ERROR
	pie = PROCESS_ERROR_INTERFACE;
	XDK_ASSERT(pie != NULL);
#endif

	plk = get_first_link(&g_xdk_mou.dump_link);
	while (plk)
	{
		nlk = get_next_link(plk);

#ifdef XDK_SUPPORT_ERROR
		dw = xsprintf(token, _T("thread dump:[thread id: %d]"), plk->tag);
		(*pie->pf_error_print)(token);
#endif

		delete_link(&g_xdk_mou.dump_link, plk);
		plk = nlk;
	}
}

void xmem_dump()
{
	link_t_ptr plk, nlk;
	dword_t tid,len;
	vword_t dump;
	xhand_t hand;
	tchar_t token[4096];

	if_thread_t* pit;
	if_error_t* pie;
	if_zone_t* pih;

	pih = THREAD_ZONE_INTERFACE;
	pit = PROCESS_THREAD_INTERFACE;

#ifdef XDK_SUPPORT_ERROR
	pie = PROCESS_ERROR_INTERFACE;
	XDK_ASSERT(pie != NULL);
#endif

	XDK_ASSERT(pih != NULL && pit != NULL);

	plk = get_first_link(&pih->if_dump);
	while (plk)
	{
		nlk = get_next_link(plk);

		dump = *((vword_t*)((byte_t*)plk + sizeof(link_t)));
		
		tid = (*pit->pf_thread_get_id)();

#ifdef XDK_SUPPORT_ERROR
#if defined(UNICODE) || defined(_UNICODE)
		len = xsprintf(token, _T("memory leak:[thread id: %d, location: %S]\n"), tid, (char*)dump);
#else
		len = xsprintf(token, _T("memory leak:[thread id: %d, location: %s]\n"), tid, (char*)dump);
#endif
		(*pie->pf_error_print)(token);
#endif

		delete_link(&pih->if_dump, plk);
		plk = nlk;
	}

	plk = get_first_link(&pih->if_hand);
	while (plk)
	{
		nlk = get_next_link(plk);

		dump = *((vword_t*)((byte_t*)plk + sizeof(link_t)));
		hand = (xhand_t)((byte_t*)plk + sizeof(link_t) + sizeof(vword_t));
		tid = (*pit->pf_thread_get_id)();

#ifdef XDK_SUPPORT_ERROR
#if defined(UNICODE) || defined(_UNICODE)
		len = xsprintf(token, _T("resource leak:[thread: %d, handle: %02X, location: %S]\n"), tid, (int)(hand->tag), (char*)dump);
#else
		len = xsprintf(token, _T("resource leak:[thread: %d, handle: %02X, location: %s]\n"), tid, (int)(hand->tag), (char*)dump);
#endif
		(*pie->pf_error_print)(token);
#endif

		delete_link(&pih->if_hand, plk);
		plk = nlk;
	}
}

#else //XDK_SUPPORT_MEMO_DUMP

void thread_dump()
{
	NOP;
}

void xmem_dump()
{
	NOP;
}

#endif //XDK_SUPPORT_THREAD

