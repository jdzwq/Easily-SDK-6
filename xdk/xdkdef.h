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

#if defined(_WIN64) || defined(__x86_64__) || defined(__amd64__)
#define _OS_64
#else
#define _OS_32
#endif

#if defined(_OS_WINDOWS)
#include "windows/_xdk_win.h"
#elif defined(_OS_MACOS)
#include "macos/_xdk_macos.h"
#elif defined(_OS_LINUX)
#include "linux/_xdk_linux.h"
#endif

#ifndef BYTE_ORDER

#define	LIT_ENDIAN	1234	/* least-significant byte first (vax, pc) */
#define	BIG_ENDIAN	4321	/* most-significant byte first (IBM, net) */
#define	PDP_ENDIAN	3412	/* LSB first in word, MSW first in int (pdp)*/

#if defined(_WIN32) || defined(_WIN64) || defined(__i386__) || defined(__x86_64__) || defined(__amd64__) || \
   defined(vax) || defined(ns32000) || defined(sun386) || \
   defined(MIPSEL) || defined(_MIPSEL) || defined(BIT_ZERO_ON_RIGHT) || \
   defined(__alpha__) || defined(__alpha)
#define BYTE_ORDER    LIT_ENDIAN
#endif

#if defined(sel) || defined(pyr) || defined(mc68000) || defined(sparc) || \
    defined(is68k) || defined(tahoe) || defined(ibm032) || defined(ibm370) || \
    defined(MIPSEB) || defined(_MIPSEB) || defined(_IBMR2) || defined(DGUX) ||\
    defined(apollo) || defined(__convex__) || defined(_CRAY) || \
    defined(__hppa) || defined(__hp9000) || \
    defined(__hp9000s300) || defined(__hp9000s700) || \
    defined (BIT_ZERO_ON_LEFT) || defined(m68k) || defined(__sparc)
#define BYTE_ORDER	BIG_ENDIAN
#endif

#endif /* BYTE_ORDER */


#ifndef LIT_ENDIAN
#define LIT_ENDIAN	__LITTLE_ENDIAN
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN	__BIG_ENDIAN
#endif

#ifndef PDP_ENDIAN
#define PDP_ENDIAN	__PDP_ENDIAN
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

#ifndef CHAR_BIT
#define CHAR_BIT  __CHAR_BIT__
#endif


#ifdef _OS_64
#define PAGE_INDI		8
#else
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
#include "gob/gobdef.h"
#include "gob/gobattr.h"

typedef struct _handle_head{
	byte_t tag; // object handle type
	byte_t lru[3]; // object reference counter
}handle_head;

#define _HANDLE_UNKNOWN		0x00

/*driver type*/
#define _DRIVER_MONOCHROME	0x01
#define _DRIVER_GRAYSCALE	0x02
#define _DRIVER_COLOR555	0x03
#define _DRIVER_COLOR888	0x04
#define _DRIVER_COLOR8888	0x05
typedef struct _handle_head	 *driver_t;

/*device type*/
#define _DEVICE_BITMAP		0x10
#define _DEVICE_PIXMAP		0x11
typedef struct _handle_head	 *device_t;

/*visual type*/
#define _VISUAL_DISPLAY		0x20
#define _VISUAL_PRINTER		0x21
#define _VISUAL_SCRIPT		0x22
#define _VISUAL_MEMORY		0x23
typedef struct _handle_head	 *visual_t;

/*canvas type*/
#define _CANVAS_DISPLAY		0x2E
#define _CANVAS_PRINTER		0x2F
typedef struct _handle_head *canvas_t;

/*network type*/
#define _HANDLE_BLOCK		0x30
#define _HANDLE_INET		0x31
#define _HANDLE_CONS		0x32
#define _HANDLE_COMM		0x33
#define _HANDLE_PIPE		0x34
#define _HANDLE_SHARE		0x35
#define _HANDLE_CACHE		0x36
#define _HANDLE_UNCF		0x37
#define _HANDLE_UDP			0x38
#define _HANDLE_TCP			0x39
#define _HANDLE_SSL			0x3A
#define _HANDLE_SSH			0x3B
#define _HANDLE_DTLS		0x3C
#define _HANDLE_TFTP		0x3D
#define _HANDLE_MQTT		0x3E
#define _HANDLE_COAP		0x3F
typedef struct _handle_head *xhand_t;

#define _HANDLE_GLYPH		0xF1
typedef struct _handle_head	*glyph_t;

#define _HANDLE_FONT		0xF2
typedef struct _handle_head	 *font_t;

#define _HANDLE_BITMAP		0xF3
typedef struct _handle_head	 *bitmap_t;

#define _HANDLE_STREAM		0xF4
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

#define UNIT_PT				_T("pt")
#define UNIT_MM				_T("mm")

#define PAPER_A4_WIDTH			210.0f
#define PAPER_A4_HEIGHT			297.0f

#define PAPER_A5_WIDTH			148.0f
#define PAPER_A5_HEIGHT			210.0f

#define PAPER_LETTER_WIDTH		210.0f
#define PAPER_LETTER_HEIGHT		280.0f

#define PAPER_MIN_WIDTH			2.6f
#define PAPER_MIN_HEIGHT		2.6f

#define PAPER_MAX_WIDTH			280.0f
#define PAPER_MAX_HEIGHT		558.7f

#define DEF_PAPER_WIDTH			PAPER_A4_WIDTH
#define DEF_PAPER_HEIGHT		PAPER_A4_HEIGHT

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

#include "log/loginf.h"
#include "bio/bioinf.h"
#include "imp/platinf.h"

#endif	/* _XDKDEF_H */

