
#include "_appdef.h"

/********************************************************************************/

void _make_ctl(const tchar_t* pathname, const tchar_t* fencode)
{
	int enc;
	dword_t dw;
	xhand_t fh = NULL;
	stream_t stm = NULL;
	bio_interface bio = { 0 };
	string_t vs_sql = NULL;
	string_t vs_txt = NULL;
	tchar_t path[PATH_LEN] = { 0 };
	tchar_t table[PATH_LEN] = { 0 };
	const tchar_t* token;
	tchar_t* text = NULL;
	int len;

	TRY_CATCH;

	fh = xuncf_open_file(NULL, pathname, FILE_OPEN_READ);
	if (!fh)
	{
		raise_user_error(_T("make_ctl"), _T("open file failed"));
	}

	enc = parse_encode(fencode);

	get_bio_interface(fh, &bio);

	stm = stream_alloc(&bio);
	stream_set_encode(stm, enc);
	stream_read_utfbom(stm, &dw);
	stream_set_mode(stm, LINE_OPERA);

	split_path(pathname, path, table, NULL);

	vs_sql = string_alloc();

	string_cat(vs_sql, _T("options(skip=1,direct=true,parallel=true)\n"), -1);
	string_cat(vs_sql, _T("load data\n"), -1);
	string_cat(vs_sql, _T("characterset UTF8\n"), -1);
	string_append(vs_sql, _T("infile '%s' \"str '\\r\\n'\"\n"), pathname);
	string_append(vs_sql, _T("append into table \"%s\"\n"), table);
	string_cat(vs_sql, _T("fields terminated by ','\n"), -1);
	string_cat(vs_sql, _T("OPTIONALLY ENCLOSED BY '\\'' AND '\\''\n"), -1);
	string_cat(vs_sql, _T("trailing nullcols\n"), -1);
	string_cat(vs_sql, _T("("), -1);

	vs_txt = string_alloc();
	stream_read_csv_line(stm, vs_txt, &dw);

	token = string_ptr(vs_txt);
	while (*token != CSV_LINEFEED && *token != _T('\0'))
	{
		len = 0;
		while(*token != CSV_ITEMFEED && *token != CSV_LINEFEED && *token != _T('\r') && *token != _T('\0'))
		{
			token ++;
			len ++;
		}

		string_cat(vs_sql, (token - len), len);
		string_cat(vs_sql, _T(",\n"), -1);

		if (*token == CSV_ITEMFEED || *token == _T('\r'))
			token++;
	}

	len = string_len(vs_sql);
	string_set_char(vs_sql, len - 2, _T(')'));
	string_set_char(vs_sql, len - 1, _T('\n'));

	string_free(vs_txt);
	vs_txt = NULL;

	stream_free(stm);
	stm = NULL;

	xuncf_close_file(fh);
	fh = NULL;

	if(!xsisnil(path))
	{
		xsncat(path, SLASH_CHAR, 1);
	}
	xscat(path, table);
	xscat(path, _T(".ctl"));

	fh = xuncf_open_file(NULL, path, FILE_OPEN_CREATE | FILE_OPEN_WRITE);
	if (!fh)
	{
		raise_user_error(_T("gen_ctl"), _T("create file failed"));
	}

	get_bio_interface(fh, &bio);

	stm = stream_alloc(&bio);
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
	_tprintf(_T("make DDL falied\n"));

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

void _make_ddl(const tchar_t* pathname, const tchar_t* fencode)
{
	int enc;
	dword_t dw;
	xhand_t fh = NULL;
	stream_t stm = NULL;
	bio_interface bio = { 0 };
	string_t vs_sql = NULL;
	string_t vs_txt = NULL;
	tchar_t path[PATH_LEN] = { 0 };
	tchar_t table[PATH_LEN] = { 0 };
	const tchar_t* token;
	tchar_t* text = NULL;
	int len;

	TRY_CATCH;

	fh = xuncf_open_file(NULL, pathname, FILE_OPEN_READ);
	if (!fh)
	{
		raise_user_error(_T("make_ddl"), _T("open file failed"));
	}

	enc = parse_encode(fencode);

	get_bio_interface(fh, &bio);

	stm = stream_alloc(&bio);
	stream_set_encode(stm, enc);
	stream_read_utfbom(stm, &dw);
	stream_set_mode(stm, LINE_OPERA);

	split_path(pathname, path, table, NULL);

	vs_sql = string_alloc();

	string_printf(vs_sql, _T("CREATE TABLE %s ( \n"), table);

	vs_txt = string_alloc();
	stream_read_csv_line(stm, vs_txt, &dw);

	token = string_ptr(vs_txt);
	while (*token != CSV_LINEFEED && *token != _T('\0'))
	{
		string_cat(vs_sql, _T("\t"), 1);

		len = 0;
		while(*token != CSV_ITEMFEED && *token != CSV_LINEFEED && *token != _T('\r') && *token != _T('\0'))
		{
			token ++;
			len ++;
		}

		string_cat(vs_sql, (token - len), len);
		string_cat(vs_sql, _T(" VARCHAR2(500) NULL,\n"), -1);

		if (*token == CSV_ITEMFEED || *token == _T('\r'))
			token++;
	}

	len = string_len(vs_sql);
	string_set_char(vs_sql, len - 2, _T(')'));
	string_set_char(vs_sql, len - 1, _T(';'));

	string_free(vs_txt);
	vs_txt = NULL;

	stream_free(stm);
	stm = NULL;

	xuncf_close_file(fh);
	fh = NULL;

	if(!xsisnil(path))
	{
		xsncat(path, SLASH_CHAR, 1);
	}
	xscat(path, table);
	xscat(path, _T(".ddl"));

	fh = xuncf_open_file(NULL, path, FILE_OPEN_CREATE | FILE_OPEN_WRITE);
	if (!fh)
	{
		raise_user_error(_T("gen_ddl"), _T("create file failed"));
	}

	get_bio_interface(fh, &bio);

	stm = stream_alloc(&bio);
	stream_set_encode(stm, _UTF8_BOM);
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
	_tprintf(_T("make DDL falied\n"));

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

void _make_sql(const tchar_t* pathname, const tchar_t* fencode)
{
	int enc;
	dword_t dw;
	xhand_t fhd_src = NULL, fhd_dst = NULL;
	stream_t stm_src = NULL, stm_dst = NULL;
	bio_interface bio_src = { 0 };
	bio_interface bio_dst = { 0 };

	string_t vs_tbl = NULL, vs_sql = NULL;
	string_t vs_txt = NULL;
	tchar_t path[PATH_LEN] = { 0 };
	tchar_t table[PATH_LEN] = { 0 };
	tchar_t sn[INT_LEN] = { 0 };
	const tchar_t* token;
	tchar_t* text = NULL;
	int len_tbl, len_sql, len, n, k = 0;

	TRY_CATCH;

	split_path(pathname, path, table, NULL);

	fhd_src = xuncf_open_file(NULL, pathname, FILE_OPEN_READ);
	if (!fhd_src)
	{
		raise_user_error(_T("gen_sql"), _T("open file failed"));
	}

	enc = parse_encode(fencode);

	get_bio_interface(fhd_src, &bio_src);
	stm_src = stream_alloc(&bio_src);
	stream_set_encode(stm_src, enc);
	stream_read_utfbom(stm_src, &dw);
	stream_set_mode(stm_src, LINE_OPERA);

	if(!xsisnil(path))
	{
		xsncat(path, SLASH_CHAR, 1);
	}
	xscat(path, table);
	xscat(path, _T(".sql"));

	fhd_dst = xuncf_open_file(NULL, path, FILE_OPEN_CREATE | FILE_OPEN_WRITE);
	if (!fhd_dst)
	{
		raise_user_error(_T("gen_sql"), _T("create file failed"));
	}

	get_bio_interface(fhd_dst, &bio_dst);
	stm_dst = stream_alloc(&bio_dst);
	stream_set_encode(stm_dst, _UTF8_BOM);
	stream_write_utfbom(stm_dst, &dw);
	stream_set_mode(stm_dst, LINE_OPERA);

	vs_tbl = string_alloc();
	string_printf(vs_tbl, _T("INSERT INTO %s ("), table);

	vs_txt = string_alloc();
	stream_read_csv_line(stm_src, vs_txt, &dw);

	vs_sql = string_alloc();

	token = string_ptr(vs_txt);
	while (*token != CSV_LINEFEED && *token != _T('\0'))
	{
		len = 0;
		while(*token != CSV_ITEMFEED && *token != CSV_LINEFEED && *token != _T('\r') && *token != _T('\0'))
		{
			token ++;
			len ++;
		}

		string_cat(vs_tbl, (token - len), len);
		string_cat(vs_tbl, _T(","), 1);

		if (*token == CSV_ITEMFEED || *token == _T('\r'))
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
		stream_read_csv_line(stm_src, vs_txt, &dw);
		if (!dw)
			break;

		string_empty(vs_sql);
		len_sql = 0;

		token = string_ptr(vs_txt);
		while (*token != CSV_LINEFEED && *token != _T('\0'))
		{
			len_sql = string_cat(vs_sql, _T("'"), 1);

			len = 0;
			while (*token != CSV_ITEMFEED && *token != CSV_LINEFEED && *token != _T('\r') && *token != _T('\0'))
			{
				token++;
				len++;
			}

			string_cat(vs_sql, (token - len), len);
			len_sql = string_cat(vs_sql, _T("',"), 2);

			if (*token == CSV_ITEMFEED || *token == _T('\r'))
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
			stream_set_encode(stm_dst, _UTF8_BOM);
			stream_write_utfbom(stm_dst, &dw);
			stream_set_mode(stm_dst, LINE_OPERA);
		}
	}

	string_cpy(vs_sql, _T("COMMIT;\n"), -1);
	stream_write_line(stm_dst, vs_sql, &dw);

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
	_tprintf(_T("make SQL falied\n"));

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
