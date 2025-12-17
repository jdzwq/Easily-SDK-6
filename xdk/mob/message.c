/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc message document

	@module	varmsg.c | message document implement file

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

#include "message.h"

#include "../xdkobj.h"
#include "../xdkstd.h"
#include "../xdkimp.h"

typedef struct _message_context{
	memo_head head;

	dword_t ver;
	byte_t qos;
	dword_t seq;
	lword_t utc;

	dword_t size;
	byte_t* data;
}message_context;

#define MESSAGE_HEAD_SIZE	16

#define MESSAGE_SET_VER(hdr,n)	PUT_DWORD_NET((hdr),0,n)
#define MESSAGE_GET_VER(hdr)	GET_DWORD_NET((hdr),0)

#define MESSAGE_GET_QOS(hdr)	GET_BYTE((hdr),4)
#define MESSAGE_SET_QOS(hdr, b)	PUT_BYTE((hdr),4,(byte_t)b)

#define MESSAGE_SET_SEQ(hdr,n)	PUT_THREEBYTE_NET((hdr),5,n)
#define MESSAGE_GET_SEQ(hdr)	GET_THREEBYTE_NET((hdr),5)

#define MESSAGE_SET_UTC(hdr,n)	PUT_LWORD_NET((hdr),8,n)
#define MESSAGE_GET_UTC(hdr)	GET_LWORD_NET((hdr),8)

#define MESSAGE_GET_BUF(msg)		(msg + MESSAGE_HEAD_SIZE)

message_t message_alloc()
{
	message_context* pmsg;

	pmsg = (message_context*)xmem_alloc(sizeof(message_context));
	pmsg->head.tag = MEM_MESSAGE;

	return (message_t)&(pmsg->head);
}

void message_free(message_t msg)
{
	message_context* pmsg = TypePtrFromHead(message_context, msg);

	XDK_ASSERT(msg && msg->tag == MEM_MESSAGE);

	if(pmsg->data) xmem_free(pmsg->data);

	xmem_free(pmsg);
}

void message_clear(message_t msg)
{
	message_context* pmsg = TypePtrFromHead(message_context, msg);

	XDK_ASSERT(msg && msg->tag == MEM_MESSAGE);

	pmsg->ver = 0;
	pmsg->qos = 0;
	pmsg->seq = 0;
	pmsg->utc = 0;

	if(pmsg->data) xmem_free(pmsg->data);

	pmsg->data = NULL;
	pmsg->size = 0;
}

dword_t message_size(message_t msg)
{
	message_context* pmsg = TypePtrFromHead(message_context, msg);

	XDK_ASSERT(msg && msg->tag == MEM_MESSAGE);

	return pmsg->size;
}

void message_borrow(message_t msg, byte_t* buf, dword_t size)
{
	message_context* pmsg = TypePtrFromHead(message_context, msg);

	XDK_ASSERT(msg && msg->tag == MEM_MESSAGE);

	pmsg->data = buf;
	pmsg->size = size;
}

byte_t* message_revert(message_t msg)
{
	message_context* pmsg = TypePtrFromHead(message_context, msg);
	byte_t* buf;

	XDK_ASSERT(msg && msg->tag == MEM_MESSAGE);

	buf = pmsg->data;
	pmsg->data = NULL;
	pmsg->size = 0;

	return buf;
}

dword_t message_write(message_t msg, const msg_hdr_t* phr, const byte_t* data, dword_t bys)
{
	message_context* pmsg = TypePtrFromHead(message_context, msg);

	XDK_ASSERT(msg && msg->tag == MEM_MESSAGE);

	if (phr)
	{
		pmsg->ver = phr->ver;
		pmsg->qos = phr->qos;
		pmsg->seq = phr->seq;
		pmsg->utc = phr->utc;
	}

	if(pmsg->data) xmem_free(pmsg->data);
	pmsg->data = NULL;
	pmsg->size = 0;

	if(data)
	{
		pmsg->data = (byte_t*)xmem_clone((void*)data, bys);
		pmsg->size = bys;
	}

	return pmsg->size;
}

dword_t message_read(message_t msg, msg_hdr_t* phr, byte_t* buff, dword_t max)
{
	message_context* pmsg = TypePtrFromHead(message_context, msg);

	XDK_ASSERT(msg && msg->tag == MEM_MESSAGE);

	if (phr)
	{
		phr->ver = pmsg->ver;
		phr->qos = pmsg->qos;
		phr->seq = pmsg->qos;
		phr->utc = pmsg->utc;
	}

	max = (max < pmsg->size)? max : pmsg->size;
	if(buff)
	{
		xmem_copy((void*)buff, (void*)pmsg->data, max);
	}

	return max;
}

/**********************************************************************
ASN.1 CER ENCODING
Message::=SEQUENCE{
	MemoHead: BYTE[4]
	MsgHead: BYTE[16]
	MsgData: BYTE[]
}
**********************************************************************/

dword_t message_encode(message_t msg, byte_t* buf)
{
	message_context* pmsg = TypePtrFromHead(message_context, msg);
	dword_t len, n, total = 0;
	byte_t* pos = NULL;
	byte_t hdr[MESSAGE_HEAD_SIZE] = {0};

	XDK_ASSERT(msg && msg->tag == MEM_MESSAGE);

	MESSAGE_SET_VER(hdr, pmsg->ver);
	MESSAGE_SET_QOS(hdr, pmsg->qos);
	MESSAGE_SET_SEQ(hdr, pmsg->seq);
	MESSAGE_SET_UTC(hdr, pmsg->utc);

	n = ver_write_sequence(((buf)? (buf + total) : NULL), &pos);
	if(!n)
	{
		set_last_error(_T("message_encode"), _T("ver_write_sequence"), -1);
		return 0;
	} 
	total += n;

	len = MESSAGE_HEAD_SIZE;
	n = ver_write_byte_array(((buf)? (buf + total) : NULL), hdr, len);
	if(!n)
	{
		set_last_error(_T("message_encode"), _T("ver_write_byte_array"), -1);
		return 0;
	} 
	total += n;
	
	len = pmsg->size;
	n = ver_write_int(((buf)? (buf + total) : NULL), len);
	if(!n)
	{
		set_last_error(_T("message_encode"), _T("ver_write_integer"), -1);
		return 0;
	} 
	total += n;

	n = ver_write_byte_array(((buf)? (buf + total) : NULL), pmsg->data, pmsg->size);
	if(!n)
	{
		set_last_error(_T("message_encode"), _T("ver_write_byte_array"), -1);
		return 0;
	} 
	total += n;

	if(pos) ver_write_sequence_length(pos, total);
	
	return total;
}

dword_t message_decode(message_t msg, const byte_t* buf)
{
	message_context* pmsg = TypePtrFromHead(message_context, msg);
	dword_t len, n, total = 0;
	byte_t hdr[MESSAGE_HEAD_SIZE] = {0};

	if(!buf) return 0;

	n = ver_read_sequence((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("message_decode"), _T("ver_read_sequence"), -1);
		return 0;
	}
	total += n;

	len = MESSAGE_HEAD_SIZE;
	n = ver_read_byte_array((buf + total), hdr, len);
	if(!n)
	{
		set_last_error(_T("message_decode"), _T("ver_read_byte_array"), -1);
		return 0;
	} 
	total += n;

	if (pmsg)
	{
		pmsg->ver = MESSAGE_GET_VER(hdr);
		pmsg->qos = MESSAGE_GET_QOS(hdr);
		pmsg->seq = MESSAGE_GET_SEQ(hdr);
		pmsg->utc = MESSAGE_GET_UTC(hdr);
	}

	n = ver_read_int((buf + total), (int*)&len);
	if(!n)
	{
		set_last_error(_T("message_decode"), _T("ver_read_int"), -1);
		return 0;
	} 
	total += n;

	if(pmsg) pmsg->size = len;

	n = ver_read_byte_array((buf + total), ((pmsg)? pmsg->data : NULL), ((pmsg)? pmsg->size : 0));
	if(!n)
	{
		set_last_error(_T("message_decode"), _T("ver_read_int"), -1);
		return 0;
	} 
	total += n;

	return total;
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void message_self_test(void)
{
	printf("test message...\n");

	byte_t buf[] = "hello world!";

	msg_hdr_t hdr = { 0 };

	message_t msg = message_alloc();

	hdr.ver = MSGVER_SENSOR;
	hdr.qos = 0x02;
	
	byte_t tmp[100] = { 0 };
	int i;

	byte_t* pb;
	dword_t bys;

	for (i = 0; i < 10; i++)
	{
		message_borrow(msg, tmp, 100);

		hdr.seq = i;
		hdr.utc = get_timestamp();

		message_write(msg, &hdr, buf, a_xslen((schar_t*)buf));
		message_read(msg, &hdr, NULL, MAX_LONG);
		printf("encodd: ver:0x%08x qos:%c seq:%d utc:%llu msg:%s\n", hdr.ver, hdr.qos, hdr.seq, hdr.utc,tmp);

		bys = message_encode(msg, NULL);
		pb = (byte_t*)xmem_alloc(bys);
		message_encode(msg, pb);
		message_decode(msg, pb);
		xmem_free(pb);
		message_read(msg, &hdr, NULL, MAX_LONG);
		printf("decode: ver:0x%08x qos:%c seq:%d utc:%llu msg:%s\n", hdr.ver, hdr.qos, hdr.seq, hdr.utc,tmp);

		message_revert(msg);
	}

	message_free(msg);

	printf("test message end\n");
}
#endif
