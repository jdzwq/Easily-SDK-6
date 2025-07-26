
#include <xdk.h>

void _error_level2()
{
	TRY_CATCH;

	raise_user_error(_T("_error_level2"), _T("level 2 error"));

	END_CATCH;

	return;
ONERROR:
	xdk_trace_last();

	return;
}

void _error_level1()
{
	TRY_CATCH;

	_error_level2();

	raise_user_error(_T("_error_level1"), _T("level 1 error"));

	END_CATCH;

	return;
ONERROR:
	xdk_trace_last();

	return;
}

void test_error()
{
	TRY_CATCH;

	_error_level1();

	raise_user_error(_T("_error_level0"), _T("level 0 error"));

	END_CATCH;

	return;
ONERROR:
	xdk_trace_last();

	XDK_TRACE_LAST;
}

void test_memo_dump()
{
	void* p;

	for(int i = 0; i < 256; i++)
	{
		p = xmem_alloc(1024);

		xmem_assert(p);

		xmem_set(p, (byte_t)i, 1024);

		if(i % 2 == 0)
		{
			xmem_free(p);
		}
	}

	xmem_dump();
}

void test_memo_page()
{
	void* p;
	dword_t dw;

	p = pmem_alloc(2050);
	dw = pmem_size(p);

	_tprintf(_T("pmem_alloc(2050) = %p, size = %d\n"), p, dw);

	p = pmem_realloc(p, 4096);

	if(pmem_lock(p) == NULL)
	{
		_tprintf(_T("pmem_lock failed\n"));
	}
	else
	{
		_tprintf(_T("pmem_lock success\n"));
	}

	xmem_set(p, (byte_t)1, 4096);

	pmem_unlock(p);
}

void test_memo_cache()
{
	xhand_t ca;
	dword_t dw;
	byte_t data[1024] = {1};

	ca = xcache_open();
	
	for(int i = 0; i < 256; i++)
	{
		dw = 1024;
		if(xcache_write(ca, data, &dw))
		{
			_tprintf(_T("xcache_write success\n"));
		}
		else
		{
			_tprintf(_T("xcache_write failed\n"));
		}
	}

	if(xcache_protect(ca, 1))
	{
		_tprintf(_T("xcache_protect success\n"));
	}
	else
	{
		_tprintf(_T("xcache_protect failed\n"));
	}

	for(int i = 0; i < 256; i++)
	{
		dw = 1024;
		if(xcache_read(ca, data, &dw))
		{
			_tprintf(_T("xcache_read success\n"));
		}
		else
		{
			_tprintf(_T("xcache_read failed\n"));
		}

		if(xcache_write(ca, data, &dw))
		{
			_tprintf(_T("xcache_write success\n"));
		}
		else
		{
			_tprintf(_T("xcache_write failed\n"));
		}
	}

	xcache_close(ca);
}

static void timer_proc_1(void* param, res_timer_t tid)
{
	int* pn = (int*)param;

	(*pn) ++;

	_tprintf(_T("the timer1 %0x scheduled %d\n"), (unsigned long)tid, *pn);
}

static void timer_proc_2(void* param, res_timer_t tid)
{
	int* pn = (int*)param;

	(*pn) ++;

	_tprintf(_T("the timer2 %0x scheduled %d\n"), (unsigned long)tid, *pn);
}

void test_timer()
{
	res_queue_t rq = 0;
	res_timer_t rt_timer1 = 0, rt_timer2 = 0;
	int timer1_count = 0;
	int timer2_count = 0;
	
	TRY_CATCH;

	rq = create_timer_queue();

	_tprintf(_T("the timer1 be started after %d second, sheduled per %d seconds\n"), 2, 2);
	rt_timer1 = create_timer(rq, 2000, 2000, (PF_TIMERFUNC)timer_proc_1, (void*)&timer1_count);

	_tprintf(_T("the timer2 be started after %d second, sheduled per %d seconds\n"), 1, 3);
	rt_timer2 = create_timer(rq, 1000, 3000, (PF_TIMERFUNC)timer_proc_2, (void*)&timer2_count);

	while(timer1_count < 10 || timer2_count < 10)
	{
		thread_sleep(1000);
	}

	destroy_timer(rq, rt_timer1);
	rt_timer1 = 0;

	destroy_timer(rq, rt_timer2);
	rt_timer2 = 0;

	destroy_timer_queue(rq);
	rq = 0;

	END_CATCH;

	return;
ONERROR:
	XDK_TRACE_LAST;

	if(rt_timer1) destroy_timer(rq, rt_timer1);

	if(rt_timer2) destroy_timer(rq, rt_timer2);

	if(rq) destroy_timer_queue(rq);

	return;
}

void test_share_cli()
{
	xhand_t ch = NULL;
	unsigned char buf[4096] = {0};
    dword_t dw = 0;

	TRY_CATCH;

    ch = xshare_cli(_T("mytest"),MAX_LONG, FILE_OPEN_CREATE);
    if(!ch)
    {
		raise_user_error(_T("test_share_cli"),_T("xshare_cli"));
	}

    a_xscpy((schar_t*)buf, "hello word!");
	dw = 4096;
    if(!xshare_write(ch, buf, &dw))
	{
		raise_user_error(_T("test_share_cli"),_T("xshare_write"));
	}

    xmem_zero((void*)buf, 4096);
    dw = 4096;
    if(!xshare_read(ch, buf, &dw))
    {
		raise_user_error(_T("test_share_cli"),_T("xshare_write"));
	}
    
    xshare_close(ch);
	ch = NULL;

	END_CATCH;

	return;
ONERROR:
	XDK_TRACE_LAST;

	if(ch) xshare_close(ch);

	return;
}

#ifndef _OS_WINDOWS
void test_share_srv()
{
    if_share_t if_share = { 0 };
    
    xdk_impl_share(&if_share);
    
	tchar_t fname[1024];
	get_runpath(0, fname, 1024);
	xscat(fname,_T("/demo.txt"));

    res_file_t fh = (*if_share.pf_share_srv)(_T("mytest"),fname,0,0,1024);
    if(fh == INVALID_FILE)
	{
        printf("parent error : %s\n", strerror(errno));
		return;
	}else{
		printf("parent share server: %s\n", "mytest");
	}
    
    char buf[4096] = {0};
    dword_t dw = 0;
    
    pid_t pid;
    int status;
    
    pid = fork();
    //kill(0, SIGSTOP);
    
    if(pid == 0)
    {
		xdk_impl_share(&if_share);

		res_file_t ch = (*if_share.pf_share_cli)(_T("mytest"), 1024, FILE_OPEN_READ);

		if (ch == INVALID_FILE)
		{
			printf("child error : %s\n", strerror(errno));
			exit(-1);
		}else
		{
			memset((void *)buf, 0, 4096);
			dw = 0;
			if (!(*if_share.pf_share_read)(ch, 0, buf, 4096, &dw))
				printf("child error : %s\n", strerror(errno));
			else
				printf("child read mytest: %s\n", buf);

			(*if_share.pf_share_close)(_T("mytest"), ch);
			exit(0);
		}
	}
    else
	{
        waitpid(pid, &status, 0);
		printf("Child exited with status: %d\n", WEXITSTATUS(status));

        (*if_share.pf_share_close)(_T("mytest"), fh);
    }
}
#endif

int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	//test_error();

	//test_memo_dump();

	//test_memo_page();

	//test_memo_cache();

	//test_share_cli();

	//test_share_srv();

	test_timer();

	xdk_process_uninit();

	return 0;
}

