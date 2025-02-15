
#include <xdk.h>

/********************************************************************************/

void cov_text(const tchar_t* pathname, const tchar_t* src_chs, const tchar_t* dst_chs)
{
	int src_enc, dst_enc;
	dword_t dw;
	xhand_t fhd_src = NULL, fhd_dst = NULL;
	stream_t stm_src = NULL, stm_dst = NULL;
	bio_interface bio_src = { 0 };
	bio_interface bio_dst = { 0 };

	string_t vs_txt = NULL;
	tchar_t path[MAX_PATH] = { 0 };
	tchar_t file[MAX_PATH] = { 0 };
	tchar_t ext[MAX_PATH] = { 0 };

	TRY_CATCH;

	split_path(pathname, path, file, ext);

	if (xsicmp(src_chs, _T("UNK")) == 0)
		src_enc = 0;
	else
		src_enc = parse_encode(src_chs);

	if (xsicmp(dst_chs, _T("UNK")) == 0)
		dst_enc = _UTF8;
	else
		dst_enc = parse_encode(dst_chs);

	if (!src_enc)
		src_enc = xuncf_file_encode(NULL, pathname);

	fhd_src = xuncf_open_file(NULL, pathname, FILE_OPEN_READ);
	if (!fhd_src)
	{
		raise_user_error(_T("cov_text"), _T("open file failed"));
	}

	get_bio_interface(fhd_src, &bio_src);
	stm_src = stream_alloc(&bio_src);
	stream_set_encode(stm_src, src_enc);
	stream_read_utfbom(stm_src, &dw);
	stream_set_mode(stm_src, LINE_OPERA);

	xscat(file, _T("-2"));
	xscat(path, file);
	if (!is_null(ext))
	{
		xscat(path, _T("."));
		xscat(path, ext);
	}

	fhd_dst = xuncf_open_file(NULL, path, FILE_OPEN_CREATE | FILE_OPEN_WRITE);
	if (!fhd_dst)
	{
		raise_user_error(_T("cov_text"), _T("create file failed"));
	}

	get_bio_interface(fhd_dst, &bio_dst);
	stm_dst = stream_alloc(&bio_dst);
	stream_set_encode(stm_dst, dst_enc);
	stream_write_utfbom(stm_dst, &dw);
	stream_set_mode(stm_dst, LINE_OPERA);

	vs_txt = string_alloc();

	while (1)
	{
		string_empty(vs_txt);
		stream_read_line(stm_src, vs_txt, &dw);
		if (!dw)
			break;

		stream_write_line(stm_dst, vs_txt, &dw);
	}

	if (stm_dst)
	{
		stream_flush(stm_dst);
		stream_free(stm_dst);
		stm_dst = NULL;
	}

	if (fhd_dst)
	{
		xuncf_close_file(fhd_dst);
		fhd_dst = NULL;
	}

	stream_free(stm_src);
	stm_src = NULL;

	xuncf_close_file(fhd_src);
	fhd_src = NULL;

	string_free(vs_txt);
	vs_txt = NULL;

	END_CATCH;

	return;

ONERROR:
	if (stm_src)
		stream_free(stm_src);

	if (fhd_src)
		xuncf_close_file(fhd_src);

	if (stm_dst)
		stream_free(stm_dst);

	if (fhd_dst)
		xuncf_close_file(fhd_dst);

	if (vs_txt)
		string_free(vs_txt);

	return;
}

int _tmain(int argc, _TCHAR* argv[]){

	tchar_t pname[MAX_PATH] = { 0 };
	tchar_t psrc[50] = { 0 };
	tchar_t pdst[50] = { 0 };

    xdk_process_init(XDK_APARTMENT_PROCESS);

	if (argc > 1)
	{
		xscpy(pname, argv[1]);
	}

	if (argc > 2)
	{
		xscpy(psrc, argv[2]);
	}

	if (argc > 3)
	{
		xscpy(pdst, argv[3]);
	}

	cov_text(pname, psrc, pdst);

    xdk_process_uninit();

    return 0;
}
