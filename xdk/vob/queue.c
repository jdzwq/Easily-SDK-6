/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc queue document

	@module	queue.c | queue document implement file

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

#include "queue.h"

#include "../xdkobj.h"
#include "../xdkstd.h"
#include "../xdkimp.h"

typedef struct _queue_context{
	memo_head head;

	int count;
	message_t* pmsg;
}queue_context;

#define QUEUE_HEAD_SIZE		(sizeof(memo_head))

#define QUEUE_GET_TYPE(que)		GET_BYTE((que),0)
#define QUEUE_SET_TYPE(que,n)	PUT_BYTE((que),0,n)

#define QUEUE_SET_SIZE(que,n)	PUT_THREEBYTE_LOC((que),1,n)
#define QUEUE_GET_SIZE(que)		(GET_THREEBYTE_LOC((que),1))

#define QUEUE_GET_BUF(que)		(que + QUEUE_HEAD_SIZE)

queue_t queue_alloc()
{
	queue_context* pq;

	pq = (queue_context*)xmem_alloc(sizeof(queue_context));
	pq->head.tag = MEM_QUEUE;

	return (queue_t)&(pq->head);
}

void queue_free(queue_t que)
{
	queue_context* pq = TypePtrFromHead(queue_context, que);
	int i;

	XDK_ASSERT(que && que->tag == MEM_QUEUE);

	for(i = 0; i < pq->count; i ++)
	{
		message_free(pq->pmsg[i]);
	}
	xmem_free(pq->pmsg);
	xmem_free(pq);
}

int queue_count(queue_t que)
{
	queue_context* pq = TypePtrFromHead(queue_context, que);

	XDK_ASSERT(que && que->tag == MEM_QUEUE);

	return pq->count;
}

int queue_write(queue_t que, message_t msg)
{
	queue_context* pq = TypePtrFromHead(queue_context, que);
	msg_hdr_t hdr_org, hdr_cur = {0};
	int i, j;

	XDK_ASSERT(que && que->tag == MEM_QUEUE);

	message_read(msg, &hdr_org, NULL, MAX_LONG);

	for(i = 0; i < pq->count; i++)
	{
		message_read(pq->pmsg[i], &hdr_cur, NULL, MAX_LONG);

		if (hdr_cur.utc <= hdr_org.utc)
		{
			break;
		}
	}

	if (hdr_cur.utc == hdr_org.utc)
	{
		message_free(pq->pmsg[i]);
		pq->pmsg[i] = msg;
	}else
	{
		pq->count ++;
		pq->pmsg = (message_t*)xmem_realloc(pq->pmsg, pq->count * sizeof(message_t));
		for(j = pq->count - 1; j > i; j--)
		{
			pq->pmsg[j] = pq->pmsg[j-1];
		}
		pq->pmsg[i] = msg;
	}

	return i;
}

message_t queue_read(queue_t que)
{
	queue_context* pq = TypePtrFromHead(queue_context, que);
	message_t msg;

	XDK_ASSERT(que && que->tag == MEM_QUEUE);

	msg = (pq->count)? pq->pmsg[pq->count - 1] : NULL;

	if(pq->count)
	{
		pq->count --;
		pq->pmsg = (message_t*)xmem_realloc(pq->pmsg, pq->count * sizeof(message_t));
	}

	return msg;
}

message_t queue_peek(queue_t que)
{
	queue_context* pq = TypePtrFromHead(queue_context, que);

	XDK_ASSERT(que && que->tag == MEM_QUEUE);

	return (pq->count)? pq->pmsg[pq->count - 1] : NULL;
}

/**********************************************************************
ASN.1 CER ENCODING
Queue::=SEQUENCE{
	MemoHead: BYTE[4]
	MsgCount: INTEGER
	MsgList: Message
}
**********************************************************************/

dword_t queue_encode(queue_t que, byte_t* buf, dword_t max)
{
	queue_context* pq = TypePtrFromHead(queue_context, que);
	dword_t len, n, total = 0;

	XDK_ASSERT(que && que->tag == MEM_QUEUE);

	
	return total;
}

dword_t queue_decode(queue_t que, const byte_t* data)
{
	queue_context* pq = TypePtrFromHead(queue_context, que);
	dword_t len, n, total = 0;

	XDK_ASSERT(que && que->tag == MEM_QUEUE);

	
	return total;
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void queue_self_test(void)
{
	printf("test queue...\n");

	byte_t buf[] = "hello world!";

	msg_hdr_t hdr = { 0 };

	message_t msg = message_alloc();

	hdr.ver = MSGVER_SENSOR;
	hdr.qos = 0x02;

	byte_t tmp[100] = { 0 };

	queue_t que = queue_alloc();
	int i;

	for (i = 0; i < 100; i++)
	{
		hdr.seq = i;
		hdr.utc = get_timestamp();

		//message_write(msg, &hdr, buf, a_xslen((schar_t*)buf));

		queue_write(que, msg);

		printf("write: ver:0x%08x qos:%c seq:%d utc:%llu msg:%s\n", hdr.ver, hdr.qos, hdr.seq, hdr.utc, buf);
	}

	while (msg = queue_read(que))
	{
		//message_read(msg, &hdr, tmp, 100);

		printf("read: ver:0x%08x qos:%c seq:%d utc:%llu msg:%s\n", hdr.ver, hdr.qos, hdr.seq, hdr.utc, tmp);
	}

	message_free(msg);

	queue_free(que);
}
#endif