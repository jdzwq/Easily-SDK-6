/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, China ZheJiang HangZhou JianDe, Mail: powersuite@hotmaol.com

	@doc xdb oci document

	@module	xdb_sqlite.c | xdb sqlite implement file

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

#include "../xdbpro.h"

#include <sqlite3.h>


#ifdef _OS_WINDOWS
#pragma comment(lib,"sqlite3.lib")
#endif

#define SQL_BREAK   _T(";")

typedef struct _xdb_sqlite_context{
	handle_head head;

	int chs;
	sqlite3* ctx;
    sqlite3_stmt* stm;
    
	bool_t trans;
	int rows;
	tchar_t err_code[NUM_LEN + 1];
	tchar_t err_text[ERR_LEN + 1];
}xdb_sqlite_context;

typedef struct _bindguid_t{
	int ind; 	//column index
	int bio; 	//input or output
	int bdt; 	//data type
	int len; 	//buffer size
	void* buf; 	//buffer 
}bindguid_t;

static void dbtodt(int type, tchar_t* dt)
{
	switch (type) {
	case SQLITE_TEXT:
		xscpy(dt, ATTR_DATA_TYPE_STRING);
		break;
	case SQLITE_INTEGER:
		xscpy(dt, ATTR_DATA_TYPE_INTEGER);
		break;
	case SQLITE_FLOAT:
		xscpy(dt, ATTR_DATA_TYPE_NUMERIC);
		break;
	case SQLITE_BLOB:
		xscpy(dt, ATTR_DATA_TYPE_STRING);
		break;
	default:
		xscpy(dt, ATTR_DATA_TYPE_STRING);
		break;
	}
}

static void decltodt(const char* decl, tchar_t* dt)
{
    if (a_xsistr(decl, "INT")) 
	{
        xscpy(dt, ATTR_DATA_TYPE_INTEGER);
    } else if (a_xsistr(decl, "REAL") || a_xsistr(decl, "FLOA") || a_xsistr(decl, "DOUB") || a_xsistr(decl, "NUMERIC") || a_xsistr(decl, "DECIMAL")) 
	{
        xscpy(dt, ATTR_DATA_TYPE_NUMERIC);
    } else if (a_xsistr(decl, "BLOB")) 
	{
        xscpy(dt, ATTR_DATA_TYPE_STRING);
    } else if (a_xsistr(decl, "CHAR") || a_xsistr(decl, "CLOB") || a_xsistr(decl, "TEXT")) 
	{
        xscpy(dt, ATTR_DATA_TYPE_STRING);
    } else if (a_xsistr(decl, "DATE") || a_xsistr(decl, "TIME")) 
	{
        xscpy(dt, ATTR_DATA_TYPE_DATETIME);
    } else 
	{
        xscpy(dt, ATTR_DATA_TYPE_STRING);
    }
}

static int split_semi(const tchar_t* token, int len)
{
	int tklen = 0, total = 0;
	bool_t glt = 0;
	const tchar_t* tkcur = token;

	if (len < 0)
		len = xslen(token);

	if (!len)
		return 0;

	while (*tkcur != _T(';') && *tkcur != _T('\0') && total < len)
	{
		if (*tkcur == _T('\'') || *tkcur == _T('\"'))
		{
			if (glt)
				glt = 0;
			else
				glt = 1;
		}

		tklen++;
		tkcur++;
		total++;

		if (glt)
		{
			while (*tkcur == _T(';'))
			{
				tklen++;
				tkcur++;
				total++;
			}
		}
	}

	return total;
}

static void _raise_ctx_error(sqlite3* ctx)
{
    tchar_t errcode[NUM_LEN + 1] = {0};
    tchar_t errtext[ERR_LEN + 1] = {0};
    
    const char* str;
    int len;
    
	str = sqlite3_errmsg(ctx);
    len = a_xslen(str);
    
#ifdef _UNICODE
	utf8_to_ucs((byte_t*)str, len, errtext, ERR_LEN);
#else
	utf8_to_mbs((byte_t*)str, len, errtext, ERR_LEN);
#endif

	xsprintf(errcode, _T("%d-%d"), sqlite3_errcode(ctx), sqlite3_extended_errcode(ctx));
    
    raise_user_error(errcode, errtext);
}

static void _db_reset(xdb_sqlite_context* pdb)
{
	xscpy(pdb->err_code, _T(""));
	xscpy(pdb->err_text, _T(""));

	pdb->rows = 0;
}

static void _db_tran(xdb_sqlite_context* pdb)
{
	char sql[MIN_SQL_LEN] = { 0 };
	int len;

#ifdef _UNICODE
	len = ucs_to_utf8(_T("BEGIN IMMEDIATE"), -1, (byte_t*)sql, MIN_SQL_LEN);
#else
	len = mbs_to_utf8(_T("BEGIN IMMEDIATE"), -1, (byte_t*)sql, MIN_SQL_LEN);
#endif
	sql[len] = '\0';

	if(SQLITE_OK != sqlite3_exec(pdb->ctx, sql, NULL, NULL, NULL))
	{
		return;
	}
    
	pdb->trans = 1;
}

static void _db_commit(xdb_sqlite_context* pdb)
{
	char sql[MIN_SQL_LEN] = { 0 };
	int len;

	if (!pdb->trans)
		return;

#ifdef _UNICODE
	len = ucs_to_utf8(_T("COMMIT"), -1, (byte_t*)sql, MIN_SQL_LEN);
#else
	len = mbs_to_utf8(_T("COMMIT"), -1, (byte_t*)sql, MIN_SQL_LEN);
#endif
	sql[len] = '\0';

	if(SQLITE_OK != sqlite3_exec(pdb->ctx, sql, NULL, NULL, NULL))
	{
		return;
	}
    
	pdb->trans = 0;
}

static void _db_rollback(xdb_sqlite_context* pdb)
{
	char sql[MIN_SQL_LEN] = { 0 };
	int len;

	if (!pdb->trans)
		return;

#ifdef _UNICODE
	len = ucs_to_utf8(_T("ROLLBACK"), -1, (byte_t*)sql, MIN_SQL_LEN);
#else
	len = mbs_to_utf8(_T("ROLLBACK"), -1, (byte_t*)sql, MIN_SQL_LEN);
#endif
	sql[len] = '\0';

	if(SQLITE_OK != sqlite3_exec(pdb->ctx, sql, NULL, NULL, NULL))
	{
		return;
	}
    
	pdb->trans = 0;
}

bool_t STDCALL db_parse_dsn(const tchar_t* dsnfile, tchar_t* srv_buf, int srv_len, tchar_t* dbn_buf, int dbn_len, tchar_t* usr_buf, int usr_len, tchar_t* pwd_buf, int pwd_len)
{
	LINKPTR d_ptr = NULL;

	TRY_CATCH;

	d_ptr = create_proper_doc();
	if (!load_proper_from_ini_file(d_ptr, NULL, dsnfile))
	{
		raise_user_error(_T("-1"), _T("parse dsn file failed"));
	}

	read_proper(d_ptr, _T("SQLITE"), -1, DSN_SERVER, -1, srv_buf, srv_len);
	read_proper(d_ptr, _T("SQLITE"), -1, DSN_DATABASE, -1, dbn_buf, dbn_len);

	destroy_proper_doc(d_ptr);
	d_ptr = NULL;

	END_CATCH;

	return 1;

ONERROR:

	if (d_ptr)
		destroy_proper_doc(d_ptr);

	return 0;
}

xdb_t STDCALL db_open_dsn(const tchar_t* dsnfile)
{
	tchar_t srv[MAX_SQL_CONN + 1] = { 0 };
	tchar_t dbn[MAX_SQL_CONN + 1] = { 0 };

	if (!db_parse_dsn(dsnfile, srv, MAX_SQL_CONN, dbn, MAX_SQL_CONN, NULL, 0, NULL, 0))
		return NULL;

	return db_open(srv, dbn, NULL, NULL);
}

xdb_t STDCALL db_open(const tchar_t* srv, const tchar_t* dbn, const tchar_t* uid, const tchar_t* pwd)
{
	xdb_sqlite_context* pdb = NULL;
	sqlite3 *ctx = NULL;

	tchar_t tconn[MAX_SQL_CONN + 1] = { 0 };
	char sconn[MAX_SQL_CONN + 1] = { 0 };

	TRY_CATCH;

	if(!is_null(srv))
	{
		xscpy(tconn, srv);
		xsncat(tconn, _T("/"), 1);
		xscat(tconn, dbn);
	}else
	{
		xscpy(tconn, dbn);
	}

#ifdef _UNICODE
    ucs_to_utf8(tconn, -1, (byte_t*)sconn, MAX_SQL_CONN);
#else
    mbs_to_utf8(tconn, -1, (byte_t*)sconn, MAX_SQL_CONN);
#endif
    
	if(SQLITE_OK != sqlite3_open(sconn, &ctx))
	{
		raise_user_error(_T("-1"), _T("Open database failed"));
	}

	pdb = (xdb_sqlite_context*)xmem_alloc(sizeof(xdb_sqlite_context));
	pdb->head.tag = _DB_SQLITE;

	pdb->ctx = ctx;

	END_CATCH;

	return (xdb_t)pdb;

ONERROR:

	if (ctx)
		sqlite3_close(ctx);

	return NULL;
}

void STDCALL db_close(xdb_t db)
{
    xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;
	
	XDK_ASSERT(pdb != NULL);

	if (pdb->stm)
	{
        sqlite3_finalize(pdb->stm);
		pdb->stm = NULL;
	}

	if(pdb->ctx)
	{
    	sqlite3_close(pdb->ctx);
		pdb->ctx = NULL;
	}
	
	xmem_free(pdb);
}


bool_t STDCALL db_datetime(xdb_t db, int diff, tchar_t* sz_time)
{
	xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;

	sqlite3_stmt *stm = NULL;
    unsigned long len = 0;
	unsigned char* sstr;
    
    char sqlstr[MID_SQL_LEN] = {0};
	int n;

	XDK_ASSERT(pdb != NULL);

	TRY_CATCH;

	_db_reset(pdb);

	if (!diff)
    {
		a_xscpy(sqlstr, "select strftime('%Y-%m-%d %H:%M:%S', datetime('now')) as DT;");
    }
	else if(diff > 0)
    {
		a_xscpy(sqlstr, "select strftime('%Y-%m-%d %H:%M:%S', ");
		a_xsappend(sqlstr, "datetime('now', '+%d day')) as DT;", diff);
    }else
	{
		a_xscpy(sqlstr, "select strftime('%Y-%m-%d %H:%M:%S', ");
		a_xsappend(sqlstr, "datetime('now', '%d day')) as DT;", diff);
	}

	if(SQLITE_OK != sqlite3_prepare_v2(pdb->ctx, sqlstr, a_xslen(sqlstr), &stm, 0))
	{
		raise_user_error(_T("-1"), _T("Alloc stm handle failed"));
	}

	if (sqlite3_step(stm) == SQLITE_ROW) 
        sstr = sqlite3_column_text(stm, 0);
    else
		sstr = NULL;

	len = a_xslen(sstr);
    
#ifdef _UNICODE
    n = utf8_to_ucs((byte_t*)sstr, len, sz_time, DATE_LEN);
#else
    n = utf8_to_mbs((byte_t*)sstr, len, sz_time, DATE_LEN);
#endif
	sz_time[n] = _T('\0');

	pdb->rows = 1;

	sqlite3_finalize(stm);
	stm = NULL;

	END_CATCH;

	return 1;

ONERROR:

	if (stm)
		sqlite3_finalize(stm);
    
	get_last_error(pdb->err_code, pdb->err_text, ERR_LEN);

	return 0;
}

bool_t STDCALL db_exec(xdb_t db, const tchar_t* sqlstr, int sqllen)
{
	xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;

    int row;
    char* d_sql = NULL;
    int d_len;
	char* serr;
    
	tchar_t *tkpre, *tkcur;
	int tklen, total;
	bool_t uni;
	int rows;

	if (sqllen < 0)
		sqllen = xslen(sqlstr);

	if (!sqllen)
	{
		return 1;
	}

	TRY_CATCH;

	XDK_ASSERT(pdb != NULL);
	
	_db_reset(pdb);

	_db_tran(pdb);

	rows = 0;
	total = 0;
	tkcur = (tchar_t*)sqlstr;
	while (*tkcur != _T('\0'))
	{
		tklen = split_line(tkcur, sqllen);

		tkpre = tkcur;
		tkcur += tklen;
		sqllen -= tklen;
		uni = 0;

		while (*tkcur == _T(' ') || *tkcur == _T('\t') || *tkcur == _T('\n') || *tkcur == _T('\r'))
		{
			if (*tkcur == _T('\r'))
				uni = 1;

			tkcur++;
			sqllen--;
		}

		if (!tklen)
		{
			continue;
		}
        
#ifdef _UNICODE
        d_len = ucs_to_utf8(tkpre, tklen, NULL, MAX_LONG);
#else
        d_len = mbs_to_utf8(tkpre, tklen, NULL, MAX_LONG);
#endif
        
        d_sql = (char*)xmem_alloc(d_len + 1);
        
#ifdef _UNICODE
        d_len = ucs_to_utf8(tkpre, tklen, (byte_t*)d_sql, d_len);
#else
        d_len = mbs_to_utf8(tkpre, tklen, (byte_t*)d_sql, d_len);
#endif

		serr = NULL;
		if (SQLITE_OK != sqlite3_exec(pdb->ctx, d_sql, 0, 0, &serr))
		{
#ifdef _UNICODE
			utf8_to_ucs(serr, a_xslen(serr), pdb->err_text, ERR_LEN);
#else
			utf8_to_mbs(serr, a_xslen(serr), pdb->err_text, ERR_LEN);
#endif
			sqlite3_free(serr);

			raise_user_error(_T("-1"), pdb->err_text);
		}

        xmem_free(d_sql);
        d_sql = NULL;
        
        row = sqlite3_changes(pdb->ctx);

		if (uni && row != 1)
		{
			raise_user_error(_T("-1"), ERR_TEXT_ROWCHANGED);
		}

		rows += (int)row;
	}

	_db_commit(pdb);

	pdb->rows = rows;

	END_CATCH;

	return 1;

ONERROR:
	get_last_error(pdb->err_code, pdb->err_text, ERR_LEN);

	_db_rollback(pdb);

    if(d_sql)
        xmem_free(d_sql);

	return 0;
}

bool_t STDCALL db_update(xdb_t db, LINKPTR grid)
{
	xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;
	
    char* d_sql = NULL;
    int d_len;
	int row;
	char* serr;

	tchar_t *sqlstr;
	int sqllen;
	LINKPTR rlk;
    dword_t rs;
	int rows;

	XDK_ASSERT(pdb != NULL);

	TRY_CATCH;

	_db_reset(pdb);

	_db_tran(pdb);

	rows = 0;
	rlk = get_next_row(grid,LINK_FIRST);
	while(rlk)
	{
		sqllen = 0;
		rs = get_row_state(rlk);
		if(rs == dsDelete)
		{
			sqllen = format_row_delete_sql(grid, rlk, NULL, MAX_LONG);
			if(sqllen > 0)
			{
				sqlstr = (tchar_t*)xmem_alloc((sqllen + 1) * sizeof(tchar_t));
				format_row_delete_sql(grid,rlk,sqlstr,sqllen);
			}
		}else if(rs == dsNewDirty)
		{
			sqllen = format_row_insert_sql(grid, rlk, NULL, MAX_LONG);
			if(sqllen > 0)
			{
				sqlstr = (tchar_t*)xmem_alloc((sqllen + 1) * sizeof(tchar_t));
				format_row_insert_sql(grid,rlk,sqlstr,sqllen);
			}
		}else if(rs == dsDirty)
		{
			sqllen = format_row_update_sql(grid, rlk, NULL, MAX_LONG);
			if(sqllen > 0)
			{
				sqlstr = (tchar_t*)xmem_alloc((sqllen + 1) * sizeof(tchar_t));
				format_row_update_sql(grid,rlk,sqlstr,sqllen);
			}
		}
		else
		{
			sqllen = 0;
		}

		if (!sqllen)
		{
			rlk = get_next_row(grid, rlk);
			continue;
		}

#ifdef _UNICODE
        d_len = ucs_to_utf8(sqlstr, sqllen, NULL, MAX_LONG);
#else
        d_len = mbs_to_utf8(sqlstr, sqllen, NULL, MAX_LONG);
#endif
        
        d_sql = (char*)xmem_alloc(d_len + 1);
        
#ifdef _UNICODE
        d_len = ucs_to_utf8(sqlstr, sqllen, (byte_t*)d_sql, d_len);
#else
        d_len = mbs_to_utf8(sqlstr, sqllen, (byte_t*)d_sql, d_len);
#endif
        
        xmem_free(sqlstr);
        sqlstr = NULL;
        
        serr = NULL;
		if (SQLITE_OK != sqlite3_exec(pdb->ctx, d_sql, 0, 0, &serr))
		{
#ifdef _UNICODE
			utf8_to_ucs(serr, a_xslen(serr), pdb->err_text, ERR_LEN);
#else
			utf8_to_mbs(serr, a_xslen(serr), pdb->err_text, ERR_LEN);
#endif
			sqlite3_free(serr);

			raise_user_error(_T("-1"), pdb->err_text);
		}

		xmem_free(d_sql);
		d_sql = NULL;

        row = sqlite3_changes(pdb->ctx);
        
		if (row != 1)
		{
			raise_user_error(_T("-1"), ERR_TEXT_ROWCHANGED);
		}
		else
		{
			rows += (int)row;
		}
        
		rlk = get_next_row(grid,rlk);
	}
	
	_db_commit(pdb);

	pdb->rows = rows;

	END_CATCH;

	return 1;

ONERROR:
	get_last_error(pdb->err_code, pdb->err_text, ERR_LEN);

	_db_rollback(pdb);

	if (sqlstr)
		xmem_free(sqlstr);
    
    if(d_sql)
        xmem_free(d_sql);

	return 0;
}

int STDCALL _db_fetch_row(xdb_sqlite_context* pdb, sqlite3_stmt* stm, LINKPTR grid)
{
	LINKPTR clk,rlk;
	
	tchar_t colname[MAX_SQL_NAME] = { 0 };
	const tchar_t* data_type;
	const tchar_t* data_cast;
	int rt, len, rows = 0;
	xdate_t dt = { 0 };

    unsigned long i, cols;
	char* sname;
	char* sdata;
	int slen;
    
    tchar_t* d_str = NULL;
    int d_len;

	cols = sqlite3_column_count(stm);
	if(!cols) return XDB_SUCCEED;

    rows = 0;
	rt = 0;
	while ((rt = sqlite3_step(stm)) == SQLITE_ROW)
	{
		rlk = insert_row(grid, LINK_LAST);
		set_row_state(rlk, dsClean);
		rows++;

		for (i = 0; i < cols; i++)
		{
			sname = sqlite3_column_name(stm, i);
#ifdef _UNICODE
			len = utf8_to_ucs((byte_t*)(sname), a_xslen(sname), colname, MAX_SQL_NAME);
#else
			len = utf8_to_mbs((byte_t*)(sname), a_xslen(sname), colname, MAX_SQL_NAME);
#endif
			colname[len] = _T('\0');

			clk = get_col(grid, colname);
			if (clk == NULL)
				continue;

			sdata = sqlite3_column_text(stm, i);
			slen = a_xslen(sdata);

#ifdef _UNICODE
			d_len = utf8_to_ucs((byte_t *)sdata, slen, NULL, MAX_LONG);
			d_str = xsalloc(d_len + 1);
			d_len = utf8_to_ucs((byte_t *)sdata, slen, d_str, d_len);

#else
			d_len = utf8_to_mbs((byte_t *)sdata, slen, NULL, MAX_LONG);
			d_str = xsalloc(d_len + 1);
			d_len = utf8_to_mbs((byte_t *)sdata, slen, d_str, d_len);
#endif

			data_type = get_col_data_type_ptr(clk);

			if (compare_text(data_type, -1, ATTR_DATA_TYPE_DATE, -1, 0) == 0 || compare_text(data_type, -1, ATTR_DATA_TYPE_DATETIME, -1, 0) == 0)
			{
				data_cast = get_col_field_cast_ptr(clk);
				if (!is_null(data_cast))
				{
					parse_datetime_ex(&dt, data_cast, d_str);
					format_datetime(&dt, d_str);
				}
			}

			set_cell_text(rlk, clk, d_str, d_len);

			xsfree(d_str);
			d_str = NULL;
		}
	}
    
	if(rt == SQLITE_DONE)
		return XDB_SUCCEED;
	else
		return XDB_FAILED;
}

bool_t STDCALL db_fetch(xdb_t db, LINKPTR grid)
{
	xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;
	
	sqlite3_stmt *stm = NULL;
	int rt;

	tchar_t* sqlstr = NULL;
	int sqllen;
    
    char* d_sql = NULL;
    int d_len;

	XDK_ASSERT(pdb != NULL);

	TRY_CATCH;

	_db_reset(pdb);

	clear_grid_rowset(grid);

	sqllen = format_grid_select_sql(grid, NULL, MAX_LONG);
	if (sqllen <= 0)
	{
		raise_user_error(_T("-1"), _T("Empty sql statement"));
	}

	sqlstr = (tchar_t*)xmem_alloc((sqllen + 1) * sizeof(tchar_t));
	format_grid_select_sql(grid,sqlstr,sqllen);
    
#ifdef _UNICODE
    d_len = ucs_to_utf8(sqlstr, sqllen, NULL, MAX_LONG);
#else
    d_len = mbs_to_utf8(sqlstr, sqllen, NULL, MAX_LONG);
#endif
    
    d_sql = (char*)xmem_alloc(d_len + 1);
    
#ifdef _UNICODE
    d_len = ucs_to_utf8(sqlstr, sqllen, (byte_t*)d_sql, d_len);
#else
    d_len = mbs_to_utf8(sqlstr, sqllen, (byte_t*)d_sql, d_len);
#endif
    
    xmem_free(sqlstr);
    sqlstr = NULL;
    
    if(SQLITE_OK != sqlite3_prepare_v2(pdb->ctx, d_sql, d_len, &stm, 0))
	{
		raise_user_error(_T("-1"), _T("Alloc stm handle failed"));
	}
    
    xmem_free(d_sql);
    d_sql = NULL;
    
	rt = XDB_PENDING;
	while (rt == XDB_PENDING)
	{
		rt = _db_fetch_row(pdb, stm, grid);
	}

	if (rt == XDB_FAILED)
	{
		raise_user_error(_T("-1"), _T("Fetch stm rows failed"));
	}

	sqlite3_finalize(stm);
	stm = NULL;

	pdb->rows = get_row_count(grid);

	END_CATCH;

	return 1;

ONERROR:
	get_last_error(pdb->err_code, pdb->err_text, ERR_LEN);

	if (sqlstr)
		xmem_free(sqlstr);
    
    if(d_sql)
        xmem_free(d_sql);

    if(stm)
        sqlite3_finalize(stm);

	return 0;
}

bool_t STDCALL db_select(xdb_t db, LINKPTR grid, const tchar_t* sqlstr)
{
	xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;
    
	LINKPTR clk;
    int sqllen;
	int i,len,cols = 0;
	tchar_t coltype[MAX_SQL_NAME] = { 0 };
	tchar_t colname[MAX_SQL_NAME] = { 0 };

    sqlite3_stmt *stm = NULL;
	int rt;
	char* sname;
	int stype;
    
    char* d_sql = NULL;
    int d_len;
    
	XDK_ASSERT(pdb != NULL);

	TRY_CATCH;
	
	_db_reset(pdb);

	clear_grid_rowset(grid);
	clear_grid_colset(grid);

	if (is_null(sqlstr))
	{
		raise_user_error(_T("-1"), _T("Empty sql statement"));
	}
    sqllen = xslen(sqlstr);
    
#ifdef _UNICODE
    d_len = ucs_to_utf8(sqlstr, sqllen, NULL, MAX_LONG);
#else
    d_len = mbs_to_utf8(sqlstr, sqllen, NULL, MAX_LONG);
#endif
    
    d_sql = (char*)xmem_alloc(d_len + 1);
    
#ifdef _UNICODE
    d_len = ucs_to_utf8(sqlstr, sqllen, (byte_t*)d_sql, d_len);
#else
    d_len = mbs_to_utf8(sqlstr, sqllen, (byte_t*)d_sql, d_len);
#endif
    
    if(SQLITE_OK != sqlite3_prepare_v2(pdb->ctx, d_sql, d_len, &stm, 0))
	{
		raise_user_error(_T("-1"), _T("Alloc stm handle failed"));
	}
    
    xmem_free(d_sql);
    d_sql = NULL;
    
    cols = sqlite3_column_count(stm);
    
	for (i = 0; i < cols; i++)
	{
        sname = sqlite3_column_name(stm, i);

		clk = insert_col(grid, LINK_LAST);

#ifdef _UNICODE
		len = utf8_to_ucs((byte_t*)sname, a_xslen(sname), colname, MAX_SQL_NAME);
#else
		len = utf8_to_mbs((byte_t*)sname, a_xslen(sname), colname, MAX_SQL_NAME);
#endif
		colname[len] = _T('\0');
        set_col_name(clk, colname);
        set_col_title(clk, colname);

		stype = sqlite3_column_type(stm, i);
        dbtodt(stype, coltype);
        set_col_data_type(clk, coltype);
	}

	rt = XDB_PENDING;
	while (rt == XDB_PENDING)
	{
		rt = _db_fetch_row(pdb, stm, grid);
	}

	if (rt == XDB_FAILED)
	{
		raise_user_error(_T("-1"), _T("Fetch stm rows failed"));
	}

	sqlite3_finalize(stm);
	stm = NULL;

	pdb->rows = get_row_count(grid);

	END_CATCH;

	return 1;

ONERROR:
	get_last_error(pdb->err_code, pdb->err_text, ERR_LEN);
    
    if(d_sql)
        xmem_free(d_sql);

	if (stm)
		sqlite3_finalize(stm);

	return 0;
}

bool_t STDCALL db_schema(xdb_t db, LINKPTR grid, const tchar_t* sqlstr)
{
    xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;
   
	LINKPTR clk;
    int sqllen;
	int i,len,cols = 0;
	tchar_t coltype[MAX_SQL_NAME] = { 0 };
	tchar_t colname[MAX_SQL_NAME] = { 0 };
	tchar_t fldname[MAX_SQL_NAME] = { 0 };
	tchar_t tblname[MAX_SQL_NAME] = { 0 };

    sqlite3_stmt *stm = NULL;
	int rt;
	char* sname;
	char* stable;
	char* sfield;
	char* stype;
    
    char* d_sql = NULL;
    int d_len;
    
	XDK_ASSERT(pdb != NULL);

	TRY_CATCH;
	
	_db_reset(pdb);

	clear_grid_rowset(grid);
	clear_grid_colset(grid);

	if (is_null(sqlstr))
	{
		raise_user_error(_T("-1"), _T("Empty sql statement"));
	}
    sqllen = xslen(sqlstr);
    
#ifdef _UNICODE
    d_len = ucs_to_utf8(sqlstr, sqllen, NULL, MAX_LONG);
#else
    d_len = mbs_to_utf8(sqlstr, sqllen, NULL, MAX_LONG);
#endif
    
    d_sql = (char*)xmem_alloc(d_len + 1);
    
#ifdef _UNICODE
    d_len = ucs_to_utf8(sqlstr, sqllen, (byte_t*)d_sql, d_len);
#else
    d_len = mbs_to_utf8(sqlstr, sqllen, (byte_t*)d_sql, d_len);
#endif
    
    if(SQLITE_OK != sqlite3_prepare_v2(pdb->ctx, d_sql, d_len, &stm, 0))
	{
		raise_user_error(_T("-1"), _T("Alloc stm handle failed"));
	}
    
    xmem_free(d_sql);
    d_sql = NULL;
    
    cols = sqlite3_column_count(stm);
    
	for (i = 0; i < cols; i++)
	{
		clk = insert_col(grid, LINK_LAST);

		sname = sqlite3_column_name(stm, i);
#ifdef _UNICODE
		len = utf8_to_ucs((byte_t*)sname, a_xslen(sname), colname, MAX_SQL_NAME);
#else
		len = utf8_to_mbs((byte_t*)sname, a_xslen(sname), colname, MAX_SQL_NAME);
#endif
		colname[len] = _T('\0');
        set_col_name(clk, colname);
        set_col_title(clk, colname);

		stype = sqlite3_column_decltype(stm, i);
        decltodt(stype, coltype);
        set_col_data_type(clk, coltype);

		stable = sqlite3_column_table_name(stm, i);
#ifdef _UNICODE
		len = utf8_to_ucs((byte_t*)stable, a_xslen(stable), tblname, MAX_SQL_NAME);
#else
		len = utf8_to_mbs((byte_t*)stable, a_xslen(stable), tblname, MAX_SQL_NAME);
#endif
		tblname[len] = _T('\0');
        set_col_table_name(clk, tblname);

		sfield = sqlite3_column_origin_name(stm, i);
#ifdef _UNICODE
		len = utf8_to_ucs((byte_t*)sfield, a_xslen(sfield), fldname, MAX_SQL_NAME);
#else
		len = utf8_to_mbs((byte_t*)sfield, a_xslen(sfield), fldname, MAX_SQL_NAME);
#endif
		fldname[len] = _T('\0');
        set_col_field_name(clk, fldname);
	}

	sqlite3_finalize(stm);
	stm = NULL;

	pdb->rows = 0;

	END_CATCH;

	return 1;

ONERROR:
	get_last_error(pdb->err_code, pdb->err_text, ERR_LEN);
    
    if(d_sql)
        xmem_free(d_sql);

	if (stm)
		sqlite3_finalize(stm);

	return 0;
}

int _db_call_argv(xdb_sqlite_context* pdb, const tchar_t* procname, const tchar_t* fmt, va_list* parg)
{
    sqlite3_stmt *stm = NULL;
    
	bindguid_t* pbind = NULL;
	int i, ind;
    tchar_t* token;
    tchar_t* ptr_str;
    int* ptr_int;
    double* ptr_double;
	int ret;

	char* d_sql = NULL;
	int d_len;
    
    TRY_CATCH;
    
    pdb->rows = 0;
    
    ind = 0;
    token = (tchar_t*)fmt;
    while (token && *token)
    {
        if (*token == '%')
            ind++;
        
        token++;
    }
    
#ifdef _UNICODE
	d_len = ucs_to_utf8(procname, -1, NULL, MAX_LONG);
#else
	d_len = mbs_to_utf8(procname, -1, NULL, MAX_LONG);
#endif
    d_len += a_xslen("select ()") + ind * 2;
    d_sql = (char*)xmem_alloc(d_len + 1);
    
    a_xsprintf(d_sql, "select %S(", procname);

    for (i = 0; i < ind; i++)
    {
        a_xscat(d_sql, "?,");
    }

	d_len = a_xslen(d_sql);
	if (d_sql[d_len - 1] == '(')
		d_len++;

	d_sql[d_len - 1] = ')';
	d_sql[d_len] = '\0';

	if(SQLITE_OK != sqlite3_prepare_v2(pdb->ctx, d_sql, d_len, &stm, 0))
	{
		raise_user_error(_T("-1"), _T("Alloc stm handle failed"));
	}
    
	xmem_free(d_sql);
	d_sql = NULL;

	pbind = (bindguid_t*)xmem_alloc(sizeof(bindguid_t) * ind);
    ind = 0;
    token = (tchar_t*)fmt;
    while (token && *token)
    {
        while (*token && *token != _T('%'))
            token++;
        
        if (!*token)
            break;
        
		pbind[ind].ind = ind + 1;

        if (*token == _T('%'))
            token++;
        
        if (*token == _T('-'))
        {
            token++;
			pbind[ind].bio = -1;
        }
        else if (*token == _T('+'))
        {
            token++;
			pbind[ind].bio = 1;
        }
        else
        {
            pbind[ind].bio = 0;
        }
        
        if (*token >= _T('0') && *token <= _T('9'))
            pbind[ind].len = xstol(token);
        
        while (*token >= _T('0') && *token <= _T('9'))
            token++;
        
        if (*token == _T('.'))
        {
            token++;
            while (*token >= _T('0') && *token <= _T('9'))
                token++;
        }
        
        switch (*token)
        {
            case _T('s'):
                ptr_str = va_arg(*parg, tchar_t*);
				if (!(pbind[ind].len))
				{
#ifdef _UNICODE
					pbind[ind].len = ucs_to_utf8(ptr_str, a_xslen(ptr_str), NULL, MAX_LONG);
#else
					pbind[ind].len = mbs_to_utf8(ptr_str, a_xslen(ptr_str), NULL, MAX_LONG);
#endif
				}

                pbind[ind].buf = (char*)xmem_alloc(pbind[ind].len + 1);
                
                if (pbind[ind].bio >= 0)
                {
#ifdef _UNICODE
					ucs_to_utf8(ptr_str, a_xslen(ptr_str), (byte_t*)(pbind[ind].buf), pbind[ind].len);
#else
					mbs_to_utf8(ptr_str, a_xslen(ptr_str), (byte_t*)(pbind[ind].buf), pbind[ind].len);
#endif
                }
                pbind[ind].bdt = SQLITE_TEXT;
                break;
            case _T('d'):
                ptr_int = va_arg(*parg, int*);
                pbind[ind].len = sizeof(int);
                pbind[ind].buf = xmem_alloc(pbind[ind].len);
                
                if (pbind[ind].bio >= 0)
                {
                    xmem_copy(pbind[ind].buf, (void*)ptr_int, sizeof(int));
                }
                pbind[ind].bdt = SQLITE_INTEGER;
                break;
            case _T('f'):
                ptr_double = va_arg(*parg, double*);
				pbind[ind].len = sizeof(double);
                pbind[ind].buf = xmem_alloc(pbind[ind].len);
                
                if (pbind[ind].bio >= 0)
                {
                    xmem_copy(pbind[ind].buf, ptr_double, sizeof(double));
                }
                pbind[ind].bdt = SQLITE_FLOAT;
                break;
        }

		switch(pbind[ind].bdt)
		{
		case SQLITE_INTEGER:
			sqlite3_bind_int(stm, pbind[ind].ind, *(int*)(pbind[ind].buf));
			break;
		case SQLITE_FLOAT:
			sqlite3_bind_double(stm, pbind[ind].ind, *(double*)(pbind[ind].buf));
			break;
		default:
			sqlite3_bind_text(stm, pbind[ind].ind, (char*)(pbind[ind].buf), pbind[ind].len, SQLITE_TRANSIENT);
			break;
		}
        
        ind ++;
    }
    
    if (sqlite3_step(stm) == SQLITE_ROW)
    {
		ret = sqlite3_column_int(stm, 0);
	}else
	{
		raise_user_error(_T("-1"), _T("Fetch stm rows failed"));
	}

	for (i = 0; i < ind; i++)
	{
		xmem_free(pbind[i].buf);
	}
	xmem_free(pbind);
	pbind = NULL;
    
    sqlite3_finalize(stm);
    stm = NULL;
    
    END_CATCH;
    
    return ret;
    
ONERROR:
    get_last_error(pdb->err_code, pdb->err_text, ERR_LEN);
      
    if (d_sql)
        xmem_free(d_sql);
    
    if(pbind)
    {
        for (i = 0; i < ind; i++)
        {
            xmem_free(pbind[i].buf);
        }
        xmem_free(pbind);
    }
    
    if (stm)
        sqlite3_finalize(stm);
    
    return -1;
}

int db_call_argv(xdb_t db, const tchar_t* procname, const tchar_t* fmt, ...)
{
    xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;
    
    va_list arg;
    int rt;
    
    va_start(arg,fmt);
    rt = _db_call_argv(pdb,procname,fmt,&arg);
    va_end(arg);
    
    return rt;
}

bool_t STDCALL db_call_func(xdb_t db, LINKPTR func)
{
    xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;
    
    sqlite3_stmt *stm = NULL;
    char* d_sql = NULL;
	int d_len;

    bindguid_t* pbind = NULL;
	int i, ind;
    tchar_t* token;
    tchar_t* ptr_str;
    int* ptr_int;
    double* ptr_double;
	int ret;
    
    LINKPTR flk;
    
    XDK_ASSERT(db && db->tag == _DB_SQLITE);
    
    TRY_CATCH;
    
    _db_reset(pdb);
    
    ind = get_func_param_count(func);

	#ifdef _UNICODE
	d_len = ucs_to_utf8(get_func_name_ptr(func), -1, NULL, MAX_LONG);
#else
	d_len = mbs_to_utf8(get_func_name_ptr(func), -1, NULL, MAX_LONG);
#endif
	d_len += a_xslen("select ()") + ind * 2;
	d_sql = (char*)xmem_alloc(d_len + 1);

	a_xsprintf(d_sql, "select %S(", get_func_name_ptr(func));

	for (i = 0; i < ind; i++)
	{
		a_xscat(d_sql, "?,");
	}

	d_len = a_xslen(d_sql);
	if (d_sql[d_len - 1] == '(')
		d_len++;
	
	d_sql[d_len - 1] = ')';
	d_sql[d_len] = '\0';
    
    if(SQLITE_OK != sqlite3_prepare_v2(pdb->ctx, d_sql, d_len, &stm, 0))
	{
		raise_user_error(_T("-1"), _T("Alloc stm handle failed"));
	}
        
    xmem_free(d_sql);
    d_sql = NULL;

    pbind = (bindguid_t*)xmem_alloc((ind) * sizeof(bindguid_t));
  
    ind = 0;
    flk = get_func_next_param(func, LINK_FIRST);
    while (flk)
    {
		pbind[ind].ind = ind + 1;

        if (compare_text(get_func_param_type_ptr(flk), -1, ATTR_PARAM_TYPE_OUTPUT, -1, 0) == 0)
        {
            pbind[ind].bio = -1;
        }
        else if (compare_text(get_func_param_type_ptr(flk), -1, ATTR_PARAM_TYPE_INPUTOUTPUT, -1, 0) == 0)
        {
            pbind[ind].bio = 1;
        }
        else
        {
            pbind[ind].bio = 0;
        }
        
        pbind[ind].len = get_func_param_data_len(flk);
        
        if (compare_text(get_func_data_type_ptr(flk), -1, ATTR_DATA_TYPE_INTEGER, -1, 0) == 0)
        {
            pbind[ind].len = sizeof(int);
            pbind[ind].buf = xmem_alloc(pbind[ind].len);
            if (pbind[ind].bio >= 0)
            {
                *(int*)(pbind[ind].buf) = get_func_param_integer(flk);
            }
        }
        else if (compare_text(get_func_data_type_ptr(flk), -1, ATTR_DATA_TYPE_NUMERIC, -1, 0) == 0)
        {
            pbind[ind].len = sizeof(double);
            pbind[ind].buf = xmem_alloc(pbind[ind].len);
            if (pbind[ind].bio >= 0)
            {
                *(double*)(pbind[ind].buf) = get_func_param_numeric(flk);
            }
        }
        else if (compare_text(get_func_data_type_ptr(flk), -1, ATTR_DATA_TYPE_DATE, -1, 0) == 0 || compare_text(get_func_data_type_ptr(flk), -1, ATTR_DATA_TYPE_DATETIME, -1, 0) == 0)
        {
            pbind[ind].len = DATE_LEN;
            pbind[ind].buf = (char*)xmem_alloc(pbind[ind].len);
			if (pbind[ind].bio >= 0)
            {
#ifdef _UNICODE
				ucs_to_utf8(get_func_param_text_ptr(flk), -1, (byte_t*)(pbind[ind].buf), pbind[ind].len);
#else
				mbs_to_utf8(get_func_param_text_ptr(flk), -1, (byte_t*)(pbind[ind].buf), pbind[ind].len);
#endif
            }
        }
        else
        {
			if (!(pbind[ind].len))
			{
#ifdef _UNICODE
				pbind[ind].len = ucs_to_utf8(get_func_param_text_ptr(flk), -1, NULL, MAX_LONG);
#else
				pbind[ind].len = mbs_to_utf8(get_func_param_text_ptr(flk), -1, NULL, MAX_LONG);
#endif
			}
            pbind[ind].buf = xmem_alloc(pbind[ind].len + 1);
            if (pbind[ind].bio >= 0)
            {
#ifdef _UNICODE
				ucs_to_utf8(get_func_param_text_ptr(flk), -1, (byte_t*)(pbind[ind].buf), pbind[ind].len);
#else
				mbs_to_utf8(get_func_param_text_ptr(flk), -1, (byte_t*)(pbind[ind].buf), pbind[ind].len);
#endif
            }
        }

		switch(pbind[ind].bdt)
		{
		case SQLITE_INTEGER:
			sqlite3_bind_int(stm, pbind[ind].ind, *(int*)(pbind[ind].buf));
			break;
		case SQLITE_FLOAT:
			sqlite3_bind_double(stm, pbind[ind].ind, *(double*)(pbind[ind].buf));
			break;
		default:
			sqlite3_bind_text(stm, pbind[ind].ind, (char*)(pbind[ind].buf), pbind[ind].len, SQLITE_TRANSIENT);
			break;
		}

        ind ++;
        flk = get_func_next_param(func, flk);
    }

	if (sqlite3_step(stm) == SQLITE_ROW)
    {
		ret = sqlite3_column_int(stm, 0);
	}else
	{
		raise_user_error(_T("-1"), _T("Fetch stm rows failed"));
	}
    
    sqlite3_finalize(stm);
    stm = NULL;

	for (i = 0; i < ind; i++)
	{
		xmem_free(pbind[i].buf);
	}
	xmem_free(pbind);
	pbind = NULL;
    
    set_func_data_type(func, ATTR_DATA_TYPE_INTEGER);
    set_func_return_integer(func, ret);
    
    END_CATCH;
    
    return 1;
    
ONERROR:
    
    if (d_sql)
        xmem_free(d_sql);
    
    if(pbind)
    {
		for (i = 0; i < ind; i++)
		{
			xmem_free(pbind[i].buf);
		}
		xmem_free(pbind);
		pbind = NULL;
	}
    
    if (stm)
        sqlite3_finalize(stm);
    
    set_func_data_type(func, ATTR_DATA_TYPE_INTEGER);
    set_func_return_integer(func, -1);
    
    return 0;
}
//////////////////////////////////////////////////////////////////////////////////////
bool_t STDCALL _db_prepare(xdb_sqlite_context* pdb, const tchar_t* sqlstr)
{
	int sqllen;
	char* d_sql = NULL;
	int d_len;
	int rc;

	XDK_ASSERT(pdb != NULL);

	TRY_CATCH;

	_db_reset(pdb);

	if (is_null(sqlstr))
	{
		raise_user_error(_T("-1"), _T("Empty sql statement"));
	}
	sqllen = xslen(sqlstr);
    
#ifdef _UNICODE
	d_len = ucs_to_utf8(sqlstr, sqllen, NULL, MAX_LONG);
#else
	d_len = mbs_to_utf8(sqlstr, sqllen, NULL, MAX_LONG);
#endif
    
	d_sql = (char*)xmem_alloc(d_len + 1);
    
#ifdef _UNICODE
	d_len = ucs_to_utf8(sqlstr, sqllen, (byte_t*)d_sql, d_len);
#else
	d_len = mbs_to_utf8(sqlstr, sqllen, (byte_t*)d_sql, d_len);
#endif
    
	if(SQLITE_OK != sqlite3_prepare_v2(pdb->ctx, d_sql, d_len, &(pdb->stm), 0))
	{
		raise_user_error(_T("-1"), _T("Alloc stm handle failed"));
	}
        
    xmem_free(d_sql);
    d_sql = NULL;

	pdb->rows = 0;
    while((rc = sqlite3_step(pdb->stm)) == SQLITE_ROW)
	{
		pdb->rows ++;
	}
	sqlite3_reset(pdb->stm); 

	if(rc != SQLITE_DONE)
	{
		raise_user_error(_T("-1"), _T("Fetch stm rows failed"));
	}

	END_CATCH;

	return 1;

ONERROR:
	get_last_error(pdb->err_code, pdb->err_text, ERR_LEN);

	if (d_sql)
		xmem_free(d_sql);

	if (pdb->stm)
	{
        sqlite3_finalize(pdb->stm);
    	pdb->stm = NULL;
	}
    
	return 0;
}

bool_t STDCALL db_export(xdb_t db, stream_t stream, const tchar_t* sqlstr)
{
	xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;

	char* sname;
	char* sdata;
	int slen;

    int i, len, cols;
    tchar_t colname[MAX_SQL_NAME] = { 0 };

	string_t vs = NULL;

	tchar_t feed[2] = { CSV_ITEMFEED, CSV_LINEFEED};

	tchar_t* sz_esc = NULL;
	int len_esc = 0;
    dword_t pos;

    tchar_t* d_str = NULL;
    int d_len;
    
	XDK_ASSERT(pdb != NULL);

	if (!pdb->stm)
	{
		_db_prepare(pdb, sqlstr);
	}

	if (!stream)
	{
		return (pdb->stm) ? 1 : 0;
	}

	TRY_CATCH;

	if (!pdb->stm)
	{
		raise_user_error(_T("-1"), ERR_TEXT_INVALIDSTMT);
	}

   	cols = sqlite3_column_count(pdb->stm);

	stream_write_utfbom(stream, NULL);

	vs = string_alloc();

	for (i = 0; i < cols; i++)
	{
		sname = sqlite3_column_name(pdb->stm, i);
		slen = a_xslen(sname);

#ifdef _UNICODE
		len = utf8_to_ucs((byte_t*)sname, slen, colname, MAX_SQL_NAME);
#else
		len = utf8_to_mbs((byte_t*)sname, slen, colname, MAX_SQL_NAME);
#endif
		colname[len] = _T('\0');
        
		string_cat(vs, colname, -1);
		if(i != cols-1)
		{
			string_cat(vs, feed, 1);
		}
	}
	string_cat(vs, feed + 1, 1);

	if (!stream_write_csv_line(stream, vs, &pos))
	{
		raise_user_error(NULL, NULL);
	}

	string_empty(vs);

    while (SQLITE_ROW == sqlite3_step(pdb->stm))
    {
		pos = 0;
		for (i = 0; i < cols; i++)
		{
			sdata = sqlite3_column_text(pdb->stm, i);
			slen = a_xslen(sdata);

#ifdef _UNICODE
            d_len = utf8_to_ucs((byte_t*)sdata,slen, NULL, MAX_LONG);
#else
            d_len = utf8_to_mbs((byte_t*)sdata, slen, NULL, MAX_LONG);
#endif
            d_str = xsalloc(d_len + 1);
#ifdef _UNICODE
            d_len = utf8_to_ucs((byte_t*)sdata, slen, d_str, d_len);
#else
            d_len = utf8_to_mbs((byte_t*)sdata, slen, d_str, d_len);
#endif

			csv_token_encode(d_str, d_len, NULL, &len_esc);
			if (len_esc != d_len)
			{
				sz_esc = xsalloc(len_esc + 1);
				csv_token_encode(d_str, d_len, sz_esc, &len_esc);

				string_cat(vs, sz_esc, len_esc);
				xsfree(sz_esc);
			}
			else
			{
				string_cat(vs, d_str, d_len);
			}
                
            xsfree(d_str);
            d_str = NULL;
			
			if(i != cols-1)
			{
				string_cat(vs, feed, 1);
			}
		}

		string_cat(vs, feed + 1, 1);

		if (!stream_write_csv_line(stream, vs, &pos))
		{
			raise_user_error(NULL, NULL);
		}

		string_empty(vs);
	}
	
	string_empty(vs);

	if (!stream_write_csv_line(stream, vs, &pos))
	{
		raise_user_error(NULL, NULL);
	}

	string_free(vs);
	vs = NULL;

	if (!stream_flush(stream))
	{
		raise_user_error(NULL, NULL);
	}
    
    sqlite3_finalize(pdb->stm);
	pdb->stm = NULL;

	END_CATCH;

	return 1;

ONERROR:
	get_last_error(pdb->err_code, pdb->err_text, ERR_LEN);

    if(d_str)
        xsfree(d_str);
    
	if (vs)
		string_free(vs);
    
    if (pdb->stm)
	{
        sqlite3_finalize(pdb->stm);
    	pdb->stm = NULL;
	}

	return 0;
}

bool_t STDCALL db_import(xdb_t db, stream_t stream, const tchar_t* table)
{
	xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;

	sqlite3_stmt *stm = NULL;
	bindguid_t* pbind = NULL;
    int i, cols;

	string_t vs = NULL;
	string_t vs_sql = NULL;
	const tchar_t* token;
    const tchar_t* tkpre;
	int tklen;
	int rows;
	dword_t dw;

	tchar_t* sz_esc = NULL;
	int len_esc = 0;
    
    char* d_sql = NULL;
    int d_len;

	XDK_ASSERT(pdb != NULL);

	XDK_ASSERT(stream != NULL);

	TRY_CATCH;

	_db_reset(pdb);

	_db_tran(pdb);

	stream_read_utfbom(stream, NULL);

	vs = string_alloc();

	dw = 0;
	if (!stream_read_csv_line(stream, vs, &dw))
	{
		raise_user_error(_T("-1"), _T("read stream failed"));
	}

	vs_sql = string_alloc();

	string_printf(vs_sql, _T("insert into %s ("), table);

	cols = 0;
	token = string_ptr(vs);
	while (*token != CSV_LINEFEED && *token != _T('\0'))
	{
		tklen = 0;
		tkpre = csv_token_split(token, -1, &tklen);

		string_cat(vs_sql, tkpre, tklen);
		string_cat(vs_sql, _T(","), 1);

		token = tkpre + tklen;
		if (*token == CSV_ITEMFEED)
			token++;

		cols++;
	}

	if (!cols)
	{
		raise_user_error(_T("-1"), _T("empty sql statement"));
	}
    
	tklen = string_len(vs_sql);
	string_set_char(vs_sql, tklen - 1, _T(')'));

	string_cat(vs_sql, _T(" values ("), -1);

	for (i = 0; i < cols; i++)
	{
		string_cat(vs_sql, _T("?,"), 2);
	}

	tklen = string_len(vs_sql);
	string_set_char(vs_sql, tklen - 1, _T(')'));

#ifdef _UNICODE
    d_len = ucs_to_utf8(string_ptr(vs_sql),string_len(vs_sql),NULL, MAX_LONG);
#else
    d_len = mbs_to_utf8(string_ptr(vs_sql),string_len(vs_sql),NULL, MAX_LONG);
#endif
    d_sql = (char*)xmem_alloc(d_len + 1);
#ifdef _UNICODE
    d_len = ucs_to_utf8(string_ptr(vs_sql),string_len(vs_sql),(byte_t*)d_sql, d_len);
#else
    d_len = mbs_to_utf8(string_ptr(vs_sql),string_len(vs_sql),(byte_t*)d_sql, d_len);
#endif
    
    string_free(vs_sql);
    vs_sql = NULL;
    
    if(SQLITE_OK != sqlite3_prepare_v2(pdb->ctx, d_sql, d_len, &stm, 0))
	{
		raise_user_error(_T("-1"), _T("Alloc stm handle failed"));
	}

    xmem_free(d_sql);
    d_sql = NULL;
    
    pbind = (bindguid_t*)xmem_alloc(sizeof(bindguid_t) * cols);

	rows = 0;
	string_empty(vs);

	while (1)
	{
		string_empty(vs);
		dw = 0;
		if (!stream_read_csv_line(stream, vs, &dw))
		{
			raise_user_error(_T("-1"), _T("stream read line failed"));
		}

		if (string_len(vs) == 0)
			break;

		i = 0;
		token = string_ptr(vs);
		while (*token != CSV_LINEFEED && *token != _T('\0'))
		{
			pbind[i].ind = i;

			tklen = 0;
			tkpre = csv_token_split(token, -1, &tklen);
	
            if(tklen)
            {
                csv_token_decode(tkpre, tklen, NULL, &len_esc);
                if (len_esc != tklen)
                {
                    sz_esc = xsalloc(len_esc + 1);
					csv_token_decode(tkpre, tklen, sz_esc, &len_esc);
                    
#ifdef _UNICODE
                    pbind[i].len = ucs_to_utf8(sz_esc, len_esc, NULL, MAX_LONG);
#else
                    pbind[i].len = mbs_to_utf8(sz_esc, len_esc, NULL, MAX_LONG);
#endif
                    pbind[i].buf = (char*)xmem_alloc(pbind[i].len + 1);
#ifdef _UNICODE
                    pbind[i].len = ucs_to_utf8(sz_esc, len_esc, (byte_t*)(pbind[i].buf), pbind[i].len);
#else
                    pbind[i].len = mbs_to_utf8(sz_esc, len_esc, (byte_t*)(pbind[i].buf), pbind[i].len);
#endif
                    
                }
                else
                {
#ifdef _UNICODE
                    pbind[i].len = ucs_to_utf8(tkpre, tklen, NULL, MAX_LONG);
#else
                    pbind[i].len= mbs_to_utf8(tkpre, tklen, NULL, MAX_LONG);
#endif
                    pbind[i].buf = (char*)xmem_alloc(pbind[i].len + 1);
#ifdef _UNICODE
                    pbind[i].len = ucs_to_utf8(tkpre, tklen, (byte_t*)(pbind[i].buf), pbind[i].len);
#else
                    pbind[i].len = mbs_to_utf8(tkpre, tklen, (byte_t*)(pbind[i].buf), pbind[i].len);
#endif
                }
            }else
            {
                pbind[i].len = 0;
				pbind[i].buf = NULL;
            }

			token = tkpre + tklen;
            if (*token == CSV_ITEMFEED)
				token++;
				
			if (++i == cols)
				break;
		}

		while (i < cols)
		{
			pbind[i].len = 0;
			pbind[i].buf = NULL;
            
			if (++i == cols)
				break;
		}

		for(i=0;i<cols;i++)
		{
			if(pbind[i].buf == NULL)
				sqlite3_bind_null(stm, i+1);
			else
				sqlite3_bind_text(stm, i+1, (char*)(pbind[i].buf), pbind[i].len, SQLITE_TRANSIENT);
		}
        
		if(sqlite3_step(stm) != SQLITE_DONE)
		{
			_raise_ctx_error(pdb->ctx);
		}

		for (i = 0; i < cols; i++)
		{
            if(pbind[i].buf)
                xmem_free(pbind[i].buf);
            
			pbind[i].len = 0;
			pbind[i].buf = NULL;
		}

		rows += (int)sqlite3_changes(pdb->ctx);

		sqlite3_reset(stm);
		sqlite3_clear_bindings(stm);
	}

	_db_commit(pdb);

	sqlite3_finalize(stm);
	stm = NULL;

    for (i = 0; i < cols; i++)
    {
        if(pbind[i].buf)
            xmem_free(pbind[i].buf);
    }
    xmem_free(pbind);

	string_free(vs);
	vs = NULL;

	pdb->rows = rows;

	END_CATCH;

	return 1;

ONERROR:
	get_last_error(pdb->err_code, pdb->err_text, ERR_LEN);

	if (stm)
	{
		_db_rollback(pdb);

		sqlite3_finalize(stm);
	}

    if(d_sql)
        xmem_free(d_sql);
    
	if (vs_sql)
		string_free(vs_sql);

	if (vs)
		string_free(vs);

    if(pbind)
    {
        for (i = 0; i < cols; i++)
        {
             if(pbind[i].buf)
            	xmem_free(pbind[i].buf);
        }
        xmem_free(pbind);
    }

	return 0;
}

bool_t STDCALL db_batch(xdb_t db, stream_t stream)
{
	xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;

	sqlite3_stmt *stm = NULL;
	char* d_sql = NULL;
    int d_len;

	string_t vs = NULL;
	string_t vs_sql = NULL;
	dword_t dw;
    
    const tchar_t *tkcur, *tkpre;
    int tklen;

	XDK_ASSERT(pdb != NULL);

	XDK_ASSERT(stream != NULL);

	TRY_CATCH;

	_db_reset(pdb);

	stream_read_utfbom(stream, NULL);

	vs = string_alloc();
	vs_sql = string_alloc();

	while (1)
	{
		string_empty(vs);
		dw = 0;
		if (!stream_read_line(stream, vs, &dw))
		{
			raise_user_error(_T("-1"), _T("stream read line failed"));
		}

		if (string_len(vs) == 0)
		{
			dw = 0;

			if (string_len(vs_sql))
				goto EXECUTE;
			else
				break;
		}

        tkcur = string_ptr(vs);
        tklen = string_len(vs);

		while (*tkcur == _T(' ') || *tkcur == _T('\t') || *tkcur == _T('\r') || *tkcur == _T('\n'))
		{
			tkcur++;
			tklen--;
		}
       
		if (*tkcur == _T('-') && *(tkcur + 1) == _T('-'))
		{
			continue;
		}

		tklen = split_semi(tkcur, tklen);

		tkpre = tkcur;
		tkcur += tklen;

		string_cat(vs_sql, tkpre, tklen);

		if (*tkcur != _T(';'))
		{
			continue;
		}

		string_empty(vs);

EXECUTE:
		string_cat(vs_sql, _T(";"), 1);
		tkpre = string_ptr(vs_sql);
		tklen = string_len(vs_sql);

#ifdef _UNICODE
		d_len = ucs_to_utf8(tkpre, tklen, NULL, MAX_LONG);
#else
		d_len = mbs_to_utf8(tkpre, tklen, NULL, MAX_LONG);
#endif

		d_sql = (char*)xmem_alloc(d_len + 1);

#ifdef _UNICODE
		d_len = ucs_to_utf8(tkpre, tklen, (byte_t*)d_sql, d_len);
#else
		d_len = mbs_to_utf8(tkpre, tklen, (byte_t*)d_sql, d_len);
#endif

		string_empty(vs_sql);

		if (SQLITE_OK != sqlite3_prepare_v2(pdb->ctx, d_sql, d_len, &stm, 0))
		{
			_raise_ctx_error((sqlite3*)pdb);
		}

		xmem_free(d_sql);
		d_sql = NULL;

		if(sqlite3_step(stm) != SQLITE_DONE)
		{
			_raise_ctx_error(pdb->ctx);
		}

		pdb->rows += sqlite3_changes((sqlite3*)stm);
		sqlite3_finalize(stm);
		stm = NULL;

		if (!dw)
			break;
	}

	string_free(vs);
	vs = NULL;

	string_free(vs_sql);
	vs_sql = NULL;

	END_CATCH;

	return 1;

ONERROR:
	get_last_error(pdb->err_code, pdb->err_text, ERR_LEN);

	if (stm)
		sqlite3_finalize(stm);
	
    if(d_sql)
         xmem_free(d_sql);
    
	if (vs)
		string_free(vs);

	if (vs_sql)
		string_free(vs_sql);

	return 0;
}

int STDCALL db_rows(xdb_t db)
{
	xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;

	XDK_ASSERT(pdb != NULL);

	return pdb->rows;
}

int STDCALL db_error(xdb_t db, tchar_t* buf, int max)
{
	xdb_sqlite_context* pdb = (xdb_sqlite_context*)db;

	XDK_ASSERT(pdb != NULL);

	max = (max < ERR_LEN) ? max : ERR_LEN;
	if (buf)
	{
		xsncpy(buf, pdb->err_text, max);
	}

	return -1;
}

bool_t STDCALL db_call_json(xdb_t db, const tchar_t* procname, LINKPTR json)
{
    NOP;
    return 0;
}


bool_t STDCALL db_read_blob(xdb_t db, stream_t stream, const tchar_t* sqlstr)
{
    NOP;
    return 0;
}

bool_t STDCALL db_write_blob(xdb_t db, stream_t stream, const tchar_t* sqlfmt)
{
    NOP;
    return 0;
}

bool_t STDCALL db_read_clob(xdb_t db, string_t varstr, const tchar_t* sqlstr)
{
    NOP;
    return 0;
}

bool_t STDCALL db_write_clob(xdb_t db, string_t varstr, const tchar_t* sqlfmt)
{
    NOP;
    return 0;
}

bool_t STDCALL db_read_xdoc(xdb_t db, LINKPTR domdoc, const tchar_t* sqlstr)
{
    NOP;
    return 0;
}

bool_t STDCALL db_write_xdoc(xdb_t db, LINKPTR domdoc, const tchar_t* sqlfmt)
{
    NOP;
    return 0;
}
