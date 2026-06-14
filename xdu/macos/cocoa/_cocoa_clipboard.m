/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc clipboard document

	@module	if_clipboard.m | macos implement file

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

#include "_if_cocoa.h"


bool_t coClipboardPut(widget_t wt, int fmt, const byte_t* data, dword_t size)
{@autoreleasepool {
	NSString *nsString;
	NSPasteboard *nsBoard;
	NSData *nsData;
	NSPasteboardItem *nsItem;

	switch(fmt)
	{
	case CB_FORMAT_MBS:
		nsString = [[NSString alloc] initWithBytes:data length:(NSUInteger)size encoding:NSUTF8StringEncoding];
		nsBoard = [NSPasteboard generalPasteboard];
        [nsBoard clearContents];
        return (YES == [nsBoard setString:nsString forType:NSPasteboardTypeString])? bool_true : bool_false;
	case CB_FORMAT_UCS:
        nsString = [[NSString alloc] initWithCharacters:(const unichar*)data length:(size / 2)];
        nsBoard = [NSPasteboard generalPasteboard];
        [nsBoard clearContents];
        return (YES == [nsBoard setString:nsString forType:NSPasteboardTypeString])? bool_true : bool_false;
	case CB_FORMAT_DIB:
		nsData = [NSData dataWithBytes:data length:(NSUInteger)size];
        nsItem = [[NSPasteboardItem alloc] init];
        if(YES != [nsItem setData:nsData forType:(NSPasteboardType)@"public.data"])
		{
			return bool_false;
		}
        nsBoard = [NSPasteboard generalPasteboard];
        [nsBoard clearContents];
        return (YES == [nsBoard writeObjects:@[nsItem]])? bool_true : bool_false;
	}
}}

dword_t coClipboardGet(widget_t wt, int fmt, byte_t* buf, dword_t max)
{@autoreleasepool {
	NSArray<NSPasteboardType> *nsPreferred = @[
        NSPasteboardTypeString,
        (NSPasteboardType)@"public.data"
    ];
	NSPasteboard *nsBoard = [NSPasteboard generalPasteboard];
	NSPasteboardType nsType = [nsBoard availableTypeFromArray:nsPreferred];
	if(!nsType) return 0;

	NSString *nsString;
	NSData *nsData;
	NSPasteboardItem *nsItem;

	switch(fmt)
	{
	case CB_FORMAT_MBS:
		if (![nsType isEqualToString:NSPasteboardTypeString]) return 0;

		nsString = [nsBoard stringForType:NSPasteboardTypeString];
        if (!nsString) return 0;

        nsData = [nsString dataUsingEncoding:NSUTF8StringEncoding];
		max = (max < (dword_t)nsData.length)? max : (dword_t)nsData.length;
        if(buf) xmem_copy((void*)buf, nsData.bytes, max);
        
		return max;
	case CB_FORMAT_UCS:
		if (![nsType isEqualToString:NSPasteboardTypeString]) return 0;

		nsString = [nsBoard stringForType:NSPasteboardTypeString];
        if (!nsString) return 0;

        CFIndex ulen = CFStringGetLength((CFStringRef)nsString);
		max = (max < 2 * ulen)? max : (2 * ulen);
        if(buf) CFStringGetCharacters((CFStringRef)nsString, CFRangeMake(0, max / 2), (UniChar*)buf);
        
		return max;
	case CB_FORMAT_DIB:
		if (![nsType isEqualToString:(NSPasteboardType)@"public.data"]) return 0;

		nsItem = nsBoard.pasteboardItems.firstObject;
        if (!nsItem) return 0;

        nsData = [nsItem dataForType:(NSPasteboardType)@"public.data"];
        if (!nsData) return 0;

		max = (max < (dword_t)nsData.length)? max : (dword_t)nsData.length;
        if(buf) xmem_copy((void*)buf, nsData.bytes, max);

		return max;
	}
}}
