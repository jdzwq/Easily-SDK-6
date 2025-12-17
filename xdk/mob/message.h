/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, China ZheJiang HangZhou JianDe, Mail: powersuite@hotmaol.com

	@doc message defination document

	@module	varmsg.h | message definition interface file

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


#ifndef _MESSAGE_H
#define	_MESSAGE_H

#include "../xdkdef.h"

#define MSGVER_SIZE		4
#define MSGHAN_SIZE		32

#define MSGVER_SENSOR	0x00000100
#define MSGVER_DECTOR	0x00010000
#define MSGVER_VENDOR	0x01000000
#define MSGID_CONFIG	0x00FFFFFF

typedef struct _msg_hdr_t{
	dword_t ver;
	byte_t qos;
	dword_t seq;
	lword_t utc;
}msg_hdr_t;

#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************************************
@FUNCTION: alloc a message.
@RETURN: message struct.
***********************************************************************/
EXP_API message_t message_alloc(void);

/**********************************************************************
@FUNCTION: free a message.
@INPUT: message struct.
@RETURN: none.
***********************************************************************/
EXP_API void message_free(message_t msg);

/**********************************************************************
@FUNCTION: clear message content.
@INPUT: message struct.
@RETURN: none.
***********************************************************************/
EXP_API void message_clear(message_t msg);

/**********************************************************************
@FUNCTION: get message data size.
@INPUT: message struct.
@RETURN: size in bytes.
***********************************************************************/
EXP_API dword_t message_size(message_t msg);

/**********************************************************************
@FUNCTION: attach outer data to message.
@INPUT: message struct.
@INPUT: outer data.
@INPUT: data size in bytes.
@RETURN: none.
***********************************************************************/
EXP_API void message_borrow(message_t msg, byte_t* data, dword_t size);

/**********************************************************************
@FUNCTION: detach message data.
@INPUT: message struct.
@RETURN: data buffer.
***********************************************************************/
EXP_API byte_t* message_revert(message_t msg);

/**********************************************************************
@FUNCTION: write data into message.
@INPUT: message struct.
@INPUT: message control header.
@INPUT: data buffer.
@INPUT: data size in bytes.
@RETURN: bytes writed.
***********************************************************************/
EXP_API	dword_t message_write(message_t msg, const msg_hdr_t* phr, const byte_t* data, dword_t bys);

/**********************************************************************
@FUNCTION: read data from message.
@INPUT: message struct.
@INPUT: message control header for reading.
@INPUT: data buffer for reading.
@INPUT: buffer size in bytes.
@RETURN: bytes readed.
***********************************************************************/
EXP_API dword_t message_read(message_t msg, msg_hdr_t* phr, byte_t* buff, dword_t max);

/**********************************************************************
@FUNCTION: encode the message to buffer.
@INPUT: message object.
@INPUT: data buffer for encoding.
@RETURN: bytes encoded, zero for failed.
@NOTE: buffer can be NULL for testing how many bytes will be encoded.
***********************************************************************/
EXP_API dword_t message_encode(message_t msg, byte_t* buf);

/**********************************************************************
@FUNCTION: decode the message from buffer.
@INPUT: message object.
@INPUT: data buffer for decoding.
@RETURN: bytes decoded, zero for failed.
@NOTE: msg can be NULL for testing how many bytes will be decoded.
***********************************************************************/
EXP_API dword_t message_decode(message_t msg, const byte_t* data);


#if defined (DEBUG) || defined (_DEBUG)
EXP_API void message_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif


#endif	/* _RADOBJ_H */

