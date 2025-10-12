/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc defination document

	@module	xdkdef.h | interface file

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


#ifndef _XDKDEF_H
#define	_XDKDEF_H


#if defined(_WIN32) || defined(WIN32) || defined(WINCE)
#define _OS_WINDOWS
#elif defined(LINUX) || defined(__LINUX__) || defined(__linux__)
#define _OS_LINUX
#elif defined(APPLE) || defined (__APPLE__) || defined (__apple__)
#define _OS_MACOS
#else
#define _OS_UNKNOW
#endif

#if defined(_WIN64) || defined(__x86_64__) || defined(__amd64__) || defined(__aarch64__)
#define _OS_64
#elif defined(_WIN32) || defined(__i386__) || defined(__arm__)
#define _OS_32
#endif

#if defined(_OS_WINDOWS)
#include "windows/_xdk_win.h"
#elif defined(_OS_MACOS)
#include "macos/_xdk_macos.h"
#elif defined(_OS_LINUX)
#include "linux/_xdk_linux.h"
#endif

#ifndef LIT_ENDIAN
#define	LIT_ENDIAN	1234	/* least-significant byte first (vax, pc) */
#endif
#ifndef BIG_ENDIAN
#define	BIG_ENDIAN	4321	/* most-significant byte first (IBM, net) */
#endif
#ifndef PDP_ENDIAN
#define	PDP_ENDIAN	3412	/* LSB first in word, MSW first in int (pdp)*/
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(__i386__) || defined(__x86_64__) || defined(__amd64__) || \
   defined(__arm__) || defined(__aarch64__) || \
   defined(vax) || defined(ns32000) || defined(sun386) || \
   defined(MIPSEL) || defined(_MIPSEL) || defined(BIT_ZERO_ON_RIGHT) || \
   defined(__alpha__) || defined(__alpha)
#define ACP_BYTE_ORDER    LIT_ENDIAN
#endif

#if defined(sel) || defined(pyr) || defined(mc68000) || defined(sparc) || \
    defined(is68k) || defined(tahoe) || defined(ibm032) || defined(ibm370) || \
    defined(MIPSEB) || defined(_MIPSEB) || defined(_IBMR2) || defined(DGUX) ||\
    defined(apollo) || defined(__convex__) || defined(_CRAY) || \
    defined(__hppa) || defined(__hp9000) || \
    defined(__hp9000s300) || defined(__hp9000s700) || \
    defined (BIT_ZERO_ON_LEFT) || defined(m68k) || defined(__sparc)
#define ACP_BYTE_ORDER	BIG_ENDIAN
#endif

#if defined(_OS_WINDOWS)
#if defined(_USRDLL)
#define EXP_API __declspec(dllexport)
#define LOC_API 
#else
#define EXP_API __declspec(dllimport)
#define LOC_API 
#endif
#else
#define EXP_API __attribute__((visibility("default"))) extern
#define LOC_API __attribute__((visibility("hidden")))
#endif


#if defined(_OS_WINDOWS)
#define STDCALL __stdcall
#else
#define STDCALL
#ifndef CALLBACK
#define CALLBACK
#endif
#endif

#ifndef _OS_WINDOWS
#if defined(_UNICODE) || defined(UNICODE)
#define _T(x)      L ## x
#else
#define _T(x)      x
#endif
#endif

#ifdef _OS_64
#define PAGE_INDI	    8
#define PAGE_ALIGN      64
#else
#define PAGE_ALIGN      32
#define PAGE_INDI		4
#endif

#ifndef PAGE_SHIFT

#if PAGE_INDI == 4
#define PAGE_SHIFT    12
#elif PAGE_INDI == 8
#define PAGE_SHIFT    13
#elif PAGE_INDI == 16
#define PAGE_SHIFT    14
#elif PAGE_INDI == 32
#define PAGE_SHIFT    15
#else
#define PAGE_SHIFT    16
#endif

#define PAGE_SIZE	(1 << PAGE_SHIFT)
#define PAGE_MASK	(~((1 << PAGE_SHIFT) - 1))

#endif /*PAGE_SHIFT*/

#ifndef PAGE_GRAN
#define PAGE_GRAN       (64 * 1024)
#endif

#ifndef PAGE_SPACE
#define PAGE_SPACE       (PAGE_GRAN * 1024)
#endif

/*CHINA LANGUAGE*/
#define LANG_CN

#include "enc/entype.h"
#include "enc/enword.h"
#include "enc/enlimit.h"
#include "enc/entoken.h"
#include "enc/encode.h"
#include "mob/mobdef.h"
#include "dob/dobdef.h"

typedef struct _handle_head{
	byte_t tag; // object handle type
	byte_t lru[3]; // object reference counter
}handle_head;

#define _HANDLE_UNKNOWN		0x00

/*resouce handle type*/
#define _HANDLE_BLOCK		0x01
#define _HANDLE_INET		0x02
#define _HANDLE_CONS		0x03
#define _HANDLE_COMM		0x04
#define _HANDLE_PIPE		0x05
#define _HANDLE_SHARE		0x06
#define _HANDLE_CACHE		0x07
#define _HANDLE_UNCF		0x08

/*network handle type*/
#define _HANDLE_UDP			0x10
#define _HANDLE_TCP			0x11
#define _HANDLE_SSL			0x12
#define _HANDLE_SSH			0x13
#define _HANDLE_DTLS		0x14
#define _HANDLE_TFTP		0x15
#define _HANDLE_MQTT		0x16
#define _HANDLE_COAP		0x17

typedef struct _handle_head *xhand_t;

#define _HANDLE_STREAM		0x1F
typedef struct _handle_head *stream_t;


/*thread function*/
#if defined(_OS_WINDOWS)
#define PF_THREADFUNC	WIN_THREAD_PROC
#elif defined(_OS_MACOS)
#define PF_THREADFUNC	MAC_THREAD_PROC
#elif defined(_OS_LINUX)
#define PF_THREADFUNC	GNU_THREAD_PROC
#endif

/*signal handler*/
#if defined(_OS_WINDOWS)
#define PF_SIGHANDLER	WIN_SIGNAL_HANDLER
#elif defined(_OS_MACOS)
#define PF_SIGHANDLER	MAC_SIGNAL_HANDLER
#elif defined(_OS_LINUX)
#define PF_SIGHANDLER	GNU_SIGNAL_HANDLER
#endif

/*timer function*/
#if defined(_OS_WINDOWS)
#define PF_TIMERFUNC	WIN_TIMER_PROC
#elif defined(_OS_MACOS)
#define PF_TIMERFUNC	MAC_TIMER_PROC
#elif defined(_OS_LINUX)
#define PF_TIMERFUNC	GNU_TIMER_PROC
#endif

#define NOP		((void*)0)

#if defined(_UNICODE) || defined(UNICODE)
#define _tprintf    wprintf
#else
#define _tprintf    printf
#endif

#ifndef _OS_WINDOWS
#ifndef min
#define min(x, y) ({                        \
    __typeof__(x) _min1 = (x);              \
    __typeof__(y) _min2 = (y);              \
    (void) (&_min1 == &_min2);              \
    _min1 < _min2 ? _min1 : _min2; })
#endif

#ifndef max
#define max(x, y) ({                         \
    __typeof__(x) _max1 = (x);               \
    __typeof__(y) _max2 = (y);               \
    (void) (&_max1 == &_max2);               \
    _max1 > _max2 ? _max1 : _max2; })
#endif
#endif

#ifdef _OS_WINDOWS
#ifndef snprintf
#define snprintf	_snprintf
#endif
#endif

#include "net/httpattr.h"
#include "net/oauthattr.h"

#include "inf/loginf.h"
#include "inf/platinf.h"
#include "inf/bioinf.h"
#include "inf/fioinf.h"

#endif	/* _XDKDEF_H */

