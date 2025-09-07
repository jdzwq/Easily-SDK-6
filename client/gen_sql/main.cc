
#include <xdk.h>

/********************************************************************************/

void gen_ddl(const tchar_t* pathname, const tchar_t* item_feed)
{
	int enc;
	dword_t dw;
	xhand_t fh = NULL;
	stream_t stm = NULL;
	bio_interface bio = { 0 };
	string_t vs_sql = NULL;
	string_t vs_txt = NULL;
	tchar_t path[MAX_PATH] = { 0 };
	tchar_t table[MAX_PATH] = { 0 };
	const tchar_t* token;
	tchar_t* text = NULL;
	int pos, len, len_feed;

	TRY_CATCH;
	
	enc = xuncf_file_encode(NULL, pathname);

	fh = xuncf_open_file(NULL, pathname, FILE_OPEN_READ);
	if (!fh)
	{
		raise_user_error(_T("gen_ddl"), _T("open file failed"));
	}

	get_bio_interface(fh, &bio);

	stm = stream_alloc(&bio);
	stream_set_encode(stm, enc);
	stream_read_utfbom(stm, &dw);
	stream_set_mode(stm, LINE_OPERA);

	split_path(pathname, path, table, NULL);

	vs_sql = string_alloc();

	string_printf(vs_sql, _T("CREATE TABLE %s (\n"), table);

	vs_txt = string_alloc();
	stream_read_line(stm, vs_txt, &dw);

	len_feed = (item_feed) ? xslen(item_feed) : 0;

	token = string_ptr(vs_txt);
	while (*token != CSV_LINEFEED && *token != _T('\0'))
	{
		string_cat(vs_sql, _T("\t"), 1);

		if (is_null(item_feed))
		{
			pos = csv_token_decode(token, NULL, &len);

			if (pos != len)
			{
				text = xsalloc(len + 1);
				csv_token_decode(token, text, &len);
				string_cat(vs_sql, text, len);
				xsfree(text);
			}
			else
			{
				if (len)
				{
					string_cat(vs_sql, token, len);
				}
			}

			token += pos;
		}
		else
		{
			pos = split_token(token, item_feed, &len);
			if (len)
			{
				string_cat(vs_sql, token, len);
			}
			token += pos;

			if (*token == _T('\r'))
				token++;
		}

		string_cat(vs_sql, _T(" VARCHAR2(100) NULL,\n"), -1);

		if (*token == CSV_ITEMFEED)
			token++;
	}

	len = string_len(vs_sql);
	string_set_char(vs_sql, len - 2, _T(')'));

	string_free(vs_txt);
	vs_txt = NULL;

	stream_free(stm);
	stm = NULL;

	xuncf_close_file(fh);
	fh = NULL;

	xscat(path, table);
	xscat(path, _T(".ddl"));

	fh = xuncf_open_file(NULL, path, FILE_OPEN_CREATE | FILE_OPEN_WRITE);
	if (!fh)
	{
		raise_user_error(_T("gen_ddl"), _T("create file failed"));
	}

	get_bio_interface(fh, &bio);

	stm = stream_alloc(&bio);
	stream_set_encode(stm, _UTF8);
	stream_write_utfbom(stm, &dw);
	stream_set_mode(stm, LINE_OPERA);

	stream_write_line(stm, vs_sql, &dw);
	stream_flush(stm);

	string_free(vs_sql);
	vs_sql = NULL;

	stream_free(stm);
	stm = NULL;

	xuncf_close_file(fh);
	fh = NULL;

	END_CATCH;

	return;

ONERROR:

	if (stm)
		stream_free(stm);

	if (fh)
		xuncf_close_file(fh);

	if (vs_sql)
		string_free(vs_sql);

	if (vs_txt)
		string_free(vs_txt);

	return;
}

void gen_sql(const tchar_t* pathname)
{
	int enc;
	dword_t dw;
	xhand_t fhd_src = NULL, fhd_dst = NULL;
	stream_t stm_src = NULL, stm_dst = NULL;
	bio_interface bio_src = { 0 };
	bio_interface bio_dst = { 0 };

	string_t vs_tbl = NULL, vs_sql = NULL;
	string_t vs_txt = NULL;
	tchar_t path[MAX_PATH] = { 0 };
	tchar_t table[MAX_PATH] = { 0 };
	tchar_t sn[INT_LEN] = { 0 };
	const tchar_t* token;
	tchar_t* text = NULL;
	int len_tbl, len_sql, pos, len, n, k = 0;

	TRY_CATCH;

	split_path(pathname, path, table, NULL);

	enc = xuncf_file_encode(NULL, pathname);

	fhd_src = xuncf_open_file(NULL, pathname, FILE_OPEN_READ);
	if (!fhd_src)
	{
		raise_user_error(_T("gen_sql"), _T("open file failed"));
	}

	get_bio_interface(fhd_src, &bio_src);
	stm_src = stream_alloc(&bio_src);
	stream_set_encode(stm_src, enc);
	stream_read_utfbom(stm_src, &dw);
	stream_set_mode(stm_src, LINE_OPERA);

	xscat(path, table);
	xscat(path, _T(".sql"));

	fhd_dst = xuncf_open_file(NULL, path, FILE_OPEN_CREATE | FILE_OPEN_WRITE);
	if (!fhd_dst)
	{
		raise_user_error(_T("gen_sql"), _T("create file failed"));
	}

	get_bio_interface(fhd_dst, &bio_dst);
	stm_dst = stream_alloc(&bio_dst);
	stream_set_encode(stm_dst, _UTF8);
	stream_write_utfbom(stm_dst, &dw);
	stream_set_mode(stm_dst, LINE_OPERA);

	vs_tbl = string_alloc();
	string_printf(vs_tbl, _T("INSERT INTO %s ("), table);

	vs_txt = string_alloc();
	stream_read_line(stm_src, vs_txt, &dw);

	vs_sql = string_alloc();

	token = string_ptr(vs_txt);
	while (*token != CSV_LINEFEED && *token != _T('\0'))
	{
		pos = csv_token_decode(token, NULL, &len);
		if (pos != len)
		{
			text = xsalloc(len + 1);
			csv_token_decode(token, text, &len);
			string_cat(vs_tbl, text, len);
			xsfree(text);
		}
		else
		{
			string_cat(vs_tbl, token, len);
		}
		token += pos;

		string_cat(vs_tbl, _T(","), 1);

		if (*token == CSV_ITEMFEED)
			token++;
	}

	len_tbl = string_len(vs_tbl);
	string_set_char(vs_tbl, len_tbl - 1, _T(')'));
	len_tbl = string_cat(vs_tbl, _T(" VALUES ("), -1);

	n = 1024;
	while (n--)
	{
		string_empty(vs_txt);
		dw = 0;
		stream_read_line(stm_src, vs_txt, &dw);
		if (!dw)
			break;

		string_empty(vs_sql);
		len_sql = 0;

		token = string_ptr(vs_txt);
		while (*token != CSV_LINEFEED && *token != _T('\0'))
		{
			len_sql = string_cat(vs_sql, _T("'"), 1);

			pos = csv_token_decode(token, NULL, &len);
			if (pos != len)
			{
				text = xsalloc(len + 1);
				csv_token_decode(token, text, &len);
				string_cat(vs_sql, text, len);
				xsfree(text);
			}
			else
			{
				string_cat(vs_sql, token, len);
			}
			token += pos;

			len_sql = string_cat(vs_sql, _T("',"), 2);

			if (*token == CSV_ITEMFEED)
				token++;
		}

		if (len_sql)
		{
			string_set_char(vs_sql, len_sql - 1, _T(')'));
		}
		len_sql = string_cat(vs_sql, _T(";\n"), 2);

		if (!n)
		{
			len_sql = string_cat(vs_sql, _T("COMMIT;\n"), -1);
			n = 1024;
			k++;
		}

		stream_write_line(stm_dst, vs_tbl, &dw);
		stream_write_line(stm_dst, vs_sql, &dw);

		if (k == 64)
		{
			stream_flush(stm_dst);
			stream_free(stm_dst);
			stm_dst = NULL;

			xuncf_close_file(fhd_dst);
			fhd_dst = NULL;

			split_path(pathname, path, table, NULL);
			k = xstol(sn);
			ltoxs(k + 1, sn, INT_LEN);
			k = 0;

			xscat(path, table);
			xscat(path, _T("-"));
			xscat(path, sn);
			xscat(path, _T(".sql"));

			fhd_dst = xuncf_open_file(NULL, path, FILE_OPEN_CREATE | FILE_OPEN_WRITE);
			if (!fhd_dst)
			{
				raise_user_error(_T("gen_sql"), _T("create file failed"));
			}

			get_bio_interface(fhd_dst, &bio_dst);
			stm_dst = stream_alloc(&bio_dst);
			stream_set_encode(stm_dst, _UTF8);
			stream_write_utfbom(stm_dst, &dw);
			stream_set_mode(stm_dst, LINE_OPERA);
		}
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

	string_free(vs_sql);
	vs_sql = NULL;

	string_free(vs_tbl);
	vs_tbl = NULL;

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

	if (vs_tbl)
		string_free(vs_tbl);

	if (vs_sql)
		string_free(vs_sql);

	if (vs_txt)
		string_free(vs_txt);

	return;
}

int _tmain(int argc, _TCHAR* argv[]){

	tchar_t pname[MAX_PATH] = { 0 };
	tchar_t param[MAX_PATH] = { 0 };
	tchar_t pval[50] = { 0 };

    xdk_process_init(XDK_APARTMENT_PROCESS);

	if (argc > 2)
	{
		xscpy(param, argv[1]);
		xscpy(pname, argv[2]);
	}
	if (argc > 3)
	{
		xscpy(pval, argv[3]);
	}

	if (compare_text(param, -1, _T("-DDL"), -1, 1) == 0)
	{
		gen_ddl(pname, pval);
	}
	else if (compare_text(param, -1, _T("-SQL"), -1, 1) == 0)
	{
		gen_sql(pname);
	}

    xdk_process_uninit();

    return 0;
}
