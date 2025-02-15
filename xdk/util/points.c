/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc utility document

	@module	points.c | implement file

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

#include "points.h"

#include "../xdkimp.h"
#include "../xdkstd.h"


int ft_parse_points_from_token(xpoint_t* ppt, int max, const tchar_t* token, int len)
{
	tchar_t *key = NULL;
	tchar_t *val = NULL;
	int klen = 0;
	int vlen = 0;
	int count = 0;
	int n, total = 0;

	if (len < 0)
		len = xslen(token);

	while (n = parse_options_token((token + total), (len - total), _T(' '), _T(','), &key, &klen, &val, &vlen))
	{
		total += n;

		if (ppt)
		{
			ppt[count].fx = xsntof(key, klen);
			ppt[count].fy = xsntof(val, vlen);
		}
		count++;
	}

	return count;
}

int ft_format_points_to_token(const xpoint_t* ppt, int n, tchar_t* buf, int max)
{
	int i;
	int len, total = 0;

	for (i = 0; i < n; i++)
	{
		len = xsprintf(NULL, _T("%.1f %.1f,"), ppt[i].fx, ppt[i].fy);
		if (len + total > max)
			return total;

		if (buf)
		{
			len = xsprintf(buf + total, _T("%.1f %.1f,"), ppt[i].fx, ppt[i].fy);
		}
		total += len;
	}

	if (total && buf)
	{
		buf[total - 1] = _T('\0');
	}

	return total;
}

int pt_parse_points_from_token(xpoint_t* ppt, int max, const tchar_t* token, int len)
{
	tchar_t *key = NULL;
	tchar_t *val = NULL;
	int klen = 0;
	int vlen = 0;
	int count = 0;
	int n, total = 0;

	if (len < 0)
		len = xslen(token);

	while (n = parse_options_token((token + total), (len - total), _T(' '), _T(','), &key, &klen, &val, &vlen))
	{
		total += n;

		if (ppt)
		{
			ppt[count].x = xsntol(key, klen);
			ppt[count].y = xsntol(val, vlen);
		}
		count++;
	}

	return count;
}

int pt_format_points_to_token(const xpoint_t* ppt, int n, tchar_t* buf, int max)
{
	int i;
	int len, total = 0;

	for (i = 0; i < n; i++)
	{
		len = xsprintf(NULL, _T("%d %d,"), ppt[i].x, ppt[i].y);
		if (len + total > max)
			return total;

		if (buf)
		{
			len = xsprintf(buf + total, _T("%d %d,"), ppt[i].x, ppt[i].y);
		}
		total += len;
	}

	if (total && buf)
	{
		buf[total - 1] = _T('\0');
	}

	return total;
}

int parse_dicm_point(const tchar_t* token, int len, xpoint_t* ppt, int max)
{
	int i, n;

	if (len < 0)
		len = xslen(token);

	if (is_null(token) || !len)
		return 0;

	i = 0;
	while (*token && len && i < max)
	{
		n = 0;
		while (*token != _T('/') && *token != _T('\\') && *token != _T('\0') && n < len)
		{
			token++;
			n++;
		}
		if (ppt)
		{
			ppt[i].x = xsntol(token - n, n);
		}

		if (*token == _T('/') || *token == _T('\\'))
		{
			token++;
			n++;
		}
		len -= n;

		n = 0;
		while (*token != _T('/') && *token != _T('\\') && *token != _T('\0') && n < len)
		{
			token++;
			n++;
		}
		if (ppt)
		{
			ppt[i].y = xsntol(token - n, n);
		}

		if (*token == _T('/') || *token == _T('\\'))
		{
			token++;
			n++;
		}
		len -= n;

		i++;
	}

	return i;
}

int format_dicm_point(const xpoint_t* ppt, int count, tchar_t* buf, int max)
{
	int i, n, total = 0;;

	for (i = 0; i < count; i++)
	{
		n = xsprintf(((buf) ? (buf + total) : NULL), _T("%d/%d/"), ppt[i].x, ppt[i].y);

		if (total + n > max)
			break;

		total += n;
	}

	if (total)
	{
		buf[total - 1] = _T('\0'); //last /
		total--;
	}

	return total;
}

bool_t inside_rowcol(int row, int col, int from_row, int from_col, int to_row, int to_col)
{
	if (row < from_row || (row == from_row && col < from_col))
		return 0;

	if (row > to_row || (row == to_row && col > to_col))
		return 0;

	return 1;
}

int compare_rowcol(int from_row, int from_col, int to_row, int to_col)
{
	if (from_row == to_row && from_col == to_col)
		return 0;
	else if (from_row == to_row && from_col < to_col)
		return -1;
	else if (from_row == to_row && from_col > to_col)
		return 1;
	else if (from_row < to_row)
		return -1;
	else
		return 1;
}

