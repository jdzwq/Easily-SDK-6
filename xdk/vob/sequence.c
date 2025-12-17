/***********************************************************************
	Easily SDK 6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc sequence buffer document

	@module	sequence.c | implement file

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

#include "sequence.h"

#include "../xdkobj.h"
#include "../xdkstd.h"
#include "../xdkimp.h"

typedef struct _sequence_frame{
		int frm_seq;		// the frame sequnce number
		dword_t frm_len;	// the frame bytes
		byte_t* frm_pkg;	// the frame data
}sequence_frame;

typedef struct _sequence_context{
	memo_head head;

	int seq_win;	// the sequecne windows
	int frm_top;	// the top sequence number
	sequence_frame** frm_list; // the frames 2-D array, one list per window
}sequence_context;

sequence_t alloc_sequence(int wins)
{
	sequence_context* plc;

	plc = (sequence_context*)xmem_alloc(sizeof(sequence_context));
	plc->head.tag = MEM_SEQUENCE;

	XDK_ASSERT(wins > 0);

	plc->frm_top = 0;

	plc->seq_win = wins;
	plc->frm_list = (sequence_frame**)xmem_alloc(wins * sizeof(sequence_frame*));

	return &(plc->head);
}

void clear_sequence(sequence_t seq)
{
	sequence_context* plc = TypePtrFromHead(sequence_context, seq);
	sequence_frame* plf;
	int i;

	XDK_ASSERT(seq != NULL && seq->tag == MEM_SEQUENCE);

	for (i = 0; i < plc->seq_win; i++)
	{
		plf = plc->frm_list[i];
		if (plf)
		{
			xmem_free(plf->frm_pkg);
			xmem_free(plf);
		}
		plc->frm_list[i] = NULL;
	}

	plc->frm_top = 0;
}

void free_sequence(sequence_t seq)
{
	sequence_context* plc = TypePtrFromHead(sequence_context, seq);

	XDK_ASSERT(seq != NULL && seq->tag == MEM_SEQUENCE);

	clear_sequence(seq);

	xmem_free(plc->frm_list);
	xmem_free(plc);
}

int get_sequence_window(sequence_t seq)
{
	sequence_context* plc = TypePtrFromHead(sequence_context, seq);

	XDK_ASSERT(seq != NULL && seq->tag == MEM_SEQUENCE);

	return plc->seq_win;
}

int get_sequence_top(sequence_t seq)
{
	sequence_context* plc = TypePtrFromHead(sequence_context, seq);

	XDK_ASSERT(seq != NULL && seq->tag == MEM_SEQUENCE);

	return plc->frm_top;
}

byte_t* insert_sequence_frame(sequence_t seq, int seqnum, dword_t frmlen)
{
	sequence_context* plc = TypePtrFromHead(sequence_context, seq);
	sequence_frame* plf;
	int pos, n;

	XDK_ASSERT(seq != NULL && seq->tag == MEM_SEQUENCE);

	pos = seqnum - plc->frm_top;

	if (pos < 0) return NULL;

	if (pos < plc->seq_win)
	{
		plf = plc->frm_list[pos];
		if (plf) return plf->frm_pkg;
	}

	plf = (sequence_frame*)xmem_alloc(sizeof(sequence_frame));
	plf->frm_pkg = (byte_t*)xmem_alloc(frmlen + 1);
	plf->frm_len = frmlen;
	plf->frm_seq = seqnum;

	// sequence number inside the window
	if (pos < plc->seq_win)
	{
		plc->frm_list[pos] = plf;
		if (!pos)
		{
			plc->frm_top = seqnum;
		}
		return plf->frm_pkg;
	}

	// sequence number outside the window, but some frame inside window must be reserved
	if (pos < 2 * plc->seq_win)
	{
		n = pos + 1 - plc->seq_win;
		for (pos = 0; pos < n; pos++)
		{
			if (plc->frm_list[pos])
			{
				xmem_free((plc->frm_list[pos])->frm_pkg);
				xmem_free(plc->frm_list[pos]);
			}
			plc->frm_list[pos] = NULL;
		}

		while (plc->frm_list[n] == NULL && n < plc->seq_win)
			n++;

		xmem_move((void*)(plc->frm_list + n), (plc->seq_win - n) * sizeof(sequence_frame*), 0 - n * sizeof(sequence_frame*));
		pos = plc->seq_win - n;
		plc->frm_list[pos] = plf;
		plc->frm_top = plc->frm_list[0]->frm_seq;

		pos++;
		while (pos < plc->seq_win)
		{
			plc->frm_list[pos++] = NULL;
		}

		return plf->frm_pkg;
	}

	// sequence number outside the window, and all frame inside window must be discard
	for (pos = 0; pos < plc->seq_win; pos++)
	{
		if (plc->frm_list[pos])
		{
			xmem_free((plc->frm_list[pos])->frm_pkg);
			xmem_free(plc->frm_list[pos]);
		}
		plc->frm_list[pos] = NULL;
	}

	// reset top frame in window
	plc->frm_list[0] = plf;
	plc->frm_top = seqnum;

	return plf->frm_pkg;
}

bool_t delete_sequence_frame(sequence_t seq, int seqnum)
{
	sequence_context* plc = TypePtrFromHead(sequence_context, seq);
	sequence_frame* plf;
	int pos;

	pos = seqnum - plc->frm_top;
	if (pos < 0 || pos > plc->seq_win - 1)
		return 0;

	plf = plc->frm_list[pos];
	if (plf)
	{
		xmem_free(plf->frm_pkg);
		xmem_free(plf);
	}
	plc->frm_list[pos] = NULL;

	return 1;
}

void clean_sequence_frame(sequence_t seq, int seqnum)
{
	sequence_context* plc = TypePtrFromHead(sequence_context, seq);
	sequence_frame* plf;
	int i, n;

	n = seqnum - plc->frm_top + 1;
	if (n <= 0) return;

	n = (n < plc->seq_win) ? n : plc->seq_win;

	for (i = 0; i < n; i++)
	{
		plf = plc->frm_list[i];
		if (plf)
		{
			xmem_free(plf->frm_pkg);
			xmem_free(plf);
		}
		plc->frm_list[i] = NULL;
	}

	while (plc->frm_list[n] == NULL && n < plc->seq_win)
		n++;

	xmem_move((void*)(plc->frm_list + n), (plc->seq_win - n) * sizeof(sequence_frame*), 0 - n * sizeof(sequence_frame*));

	i = plc->seq_win - n;
	while (i < plc->seq_win)
	{
		plc->frm_list[i] = NULL;
		i++;
	}

	plf = plc->frm_list[0];
	plc->frm_top = (plf) ? plf->frm_seq : (seqnum + 1);
}

byte_t* get_sequence_frame(sequence_t seq, int seqnum, dword_t* pb)
{
	sequence_context* plc = TypePtrFromHead(sequence_context, seq);
	sequence_frame* plf;
	int pos;

	pos = seqnum - plc->frm_top;
	if (pos < 0 || pos > plc->seq_win - 1) return 0;

	plf = plc->frm_list[pos];
	if (!plf)
	{
		if (pb) *pb = 0;
		return NULL;
	}
	
	if (pb) *pb = plf->frm_len;

	return plf->frm_pkg;
}

bool_t set_sequence_frame(sequence_t seq, int seqnum, const byte_t* frame, dword_t size)
{
	sequence_context* plc = TypePtrFromHead(sequence_context, seq);
	sequence_frame* plf;
	int pos;

	pos = seqnum - plc->frm_top;
	if (pos < 0 || pos > plc->seq_win - 1) return 0;

	plf = plc->frm_list[pos];
	if (!plf)
	{
		plf = (sequence_frame*)xmem_alloc(sizeof(sequence_frame));
		plf->frm_seq = seqnum;
		plc->frm_list[pos] = plf;
	}

	plf->frm_pkg = (byte_t*)xmem_realloc(plf->frm_pkg, size + 1);
	xmem_copy((void*)plf->frm_pkg, (void*)frame, size);
	plf->frm_len = size;

	return 1;
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void sequence_self_test()
{
	sequence_t lin = alloc_sequence(3);

	byte_t* buf;
	dword_t len;

	int i;
	printf("test sequence...\n");

	for (i = 0; i < 10; i++)
	{
		buf = insert_sequence_frame(lin, i + 1, 8);

		a_xsprintf((schar_t*)buf, "%08X", (i + 1));

		if (!((i+1) % 3))
			clean_sequence_frame(lin, i+1);
	}

	for (i = 0; i < 10; i++)
	{
		buf = get_sequence_frame(lin, (i+1), &len);
		printf("sequence: %s\n", (const char*)buf);
	}

	free_sequence(lin);
}
#endif