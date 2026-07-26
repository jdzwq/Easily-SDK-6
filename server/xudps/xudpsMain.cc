

#include "xudps.h"
#include "../srvlog.h"

#ifdef _OS_WINDOWS
#pragma comment( linker, "/subsystem:windows /entry:mainCRTStartup" )
#endif

xudps_param_t xp = { 0 };


int main(int argc, char* argv[])
{
	xhand_t pipe = NULL;
	stream_t stm = NULL;
	bio_interface bio = { 0 };

	unsigned short port = 0;
	byte_t addr[ADDR_LEN + 1] = { 0 };
	dword_t alen = 0;
	byte_t pack[UDP_PKG_SIZE] = { 0 };
	dword_t size = 0;
	dword_t dw;
	byte_t num[2] = { 0 };
	tchar_t tddr[ADDR_LEN + 1] = { 0 };
	xhand_t udp = NULL;

	int i, len;

	tchar_t sz_secu[RES_LEN + 1] = { 0 };

	tchar_t errcode[NUM_LEN + 1] = { 0 };
	tchar_t errtext[ERR_LEN + 1] = { 0 };

	xdk_process_init(XDK_APARTMENT_PROCESS | XDK_INITIALIZE_SERVER);

	TRY_CATCH;

	for (i = 1; i < argc; i++)
	{
		if (a_xsisnil(argv[i]))
			continue;

		len = xslen(xp.sz_param);
#ifdef _UNICODE
		mbs_to_ucs((const schar_t*)argv[i], -1, xp.sz_param + len, PATH_LEN - len);
#else
		a_xsncpy(xp.sz_param + len, argv[i], PATH_LEN - len);
#endif
		xsncat(xp.sz_param, _T(" "), 1);
	}

	get_param_item(xp.sz_param, XPORTD_PARAM_SECURITY, sz_secu, RES_LEN);

	if (compare_text(sz_secu, 3, XPORTD_PARAM_SECURITY_SSL, 3, 1) == 0)
		xp.n_secu = _SECU_SSL;
	else if (compare_text(sz_secu, 3, XPORTD_PARAM_SECURITY_SSH, 3, 1) == 0)
		xp.n_secu = _SECU_SSH;
	else
		xp.n_secu = _SECU_NONE;

	pipe = xpipe_srv(NULL, FILE_OPEN_READ);
	if (!pipe)
	{
		raise_user_error(_T("-1"), _T("child process create std pipe failed"));
	}

	get_bio_interface(pipe, &bio);

	stm = stream_alloc(&bio);
	if (!stm)
	{
		raise_user_error(_T("-1"), _T("child process create steam failed"));
	}

	stream_set_mode(stm, CHUNK_OPERA);

	if (!stream_read_chunk_size(stm, &dw))
	{
		raise_user_error(_T("-1"), _T("child process read port failed"));
	}
	if (dw != 2)
	{
		raise_user_error(_T("-1"), _T("invalid port size"));
	}
	stream_read_bytes(stm, num, &dw);
	port = GET_SWORD_NET(num, 0);

	if (!stream_read_chunk_size(stm, &dw))
	{
		raise_user_error(_T("-1"), _T("child process read addr failed"));
	}
	if (dw > ADDR_LEN)
	{
		raise_user_error(_T("-1"), _T("invalid addr size"));
	}
	stream_read_bytes(stm, addr, &dw);
	alen = a_xslen((schar_t*)addr);

	if (!stream_read_chunk_size(stm, &dw))
	{
		raise_user_error(_T("-1"), _T("child process read pack failed"));
	}
	if (dw > UDP_PKG_SIZE)
	{
		raise_user_error(_T("-1"), _T("invalid pack size"));
	}
	stream_read_bytes(stm, pack, &dw);
	size = dw;

	//terminated
	stream_read_chunk_size(stm, &dw);

	stream_free(stm);
	stm = NULL;

	xpipe_free(pipe);
	pipe = NULL;

#ifdef _UNICODE
	alen = mbs_to_ucs((schar_t*)addr, alen, tddr, ADDR_LEN);
#else
	alen = mbs_to_mbs((schar_t*)addr, alen, tddr, ADDR_LEN);
#endif
	tddr[alen] = _T('\0');

	if (xp.n_secu == _SECU_DTLS)
		udp = xdtls_srv(port, tddr, pack, size);
	else
		udp = xudp_srv(port, tddr, pack, size);

	if (!udp)
	{
		raise_user_error(_T("-1"), _T("child process create udp server failed"));
	}

	_xudps_dispatch(udp, (void*)&xp);

	if (xp.n_secu == _SECU_SSL)
		xdtls_close(udp);
	else
		xudp_close(udp);

	udp = NULL;

	xportm_log_error(_T("xudps"), _T("process terminated"));

	END_CATCH;

	xdk_process_uninit();

	return 0;

ONERROR:

	get_last_error(errcode, errtext, ERR_LEN);

	if (pipe)
		xpipe_free(pipe);

	if (stm)
		stream_free(stm);

	if (udp)
	{
		if (xp.n_secu == _SECU_SSL)
			xdtls_close(udp);
		else
			xudp_close(udp);
	}

	xportm_log_error(errcode, errtext);

	xdk_process_uninit();

	return -1;
}

