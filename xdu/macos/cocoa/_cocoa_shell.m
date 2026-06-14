/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc shell document

	@module	if_shell.m | macos implement file

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

bool_t coShellGetFileName(widget_t wt, const tchar_t* defpath, const tchar_t* filter, const tchar_t* defext, bool_t saveit, tchar_t* pathbuf, int pathlen, tchar_t* filebuf, int filelen)
{@autoreleasepool {
    NSSavePanel *panelSave = nil;
    NSOpenPanel *panelOpen = nil;
    NSSavePanel *panel = nil;

    if (saveit) 
    {
        panelSave = [NSSavePanel savePanel];
        if (defext && *defext)
        {
            panelSave.allowedFileTypes = @[ [NSString stringWithUTF8String:defext] ];
        }

        panel = panelSave;
    } else 
    {
        panelOpen = [NSOpenPanel openPanel];
        panelOpen.canChooseFiles = YES;
        panelOpen.canChooseDirectories = NO;
        panelOpen.allowsMultipleSelection = NO;

        panel = (NSSavePanel*)panelOpen;
    }

    if (defpath && *defpath) {
        NSString *nsDir = [NSString stringWithUTF8String:defpath];
        panel.directoryURL = [NSURL fileURLWithPath:nsDir];
    }

    if(!saveit && filter && *filter)
    {
        NSMutableArray *tabExts = [NSMutableArray array];
        filter += (xslen(filter) + 1);
        while(filter && *filter)
        {
            NSString *nsExt = [NSString stringWithUTF8String:filter];
            if ([nsExt hasPrefix:@"*."]) nsExt = [nsExt substringFromIndex:2];
            if ([nsExt hasPrefix:@"."])  nsExt = [nsExt substringFromIndex:1];
            if (nsExt.length) [tabExts addObject:nsExt];

            filter += (xslen(filter) + 1);
        }

        if (tabExts.count)
        {
            [(NSOpenPanel*)panel setAllowedFileTypes:tabExts];
        }
    }

    if ([panel runModal] != NSModalResponseOK)
        return 0;

    NSURL *nsUrl = saveit ? [panelSave URL] : [[panelOpen URLs] firstObject];
    if (!nsUrl) return 0;

    NSString *nsFull = nsUrl.path;
    NSString *nsFile = nsFull.lastPathComponent;
    NSString *nsPath   = [nsFull stringByDeletingLastPathComponent];

    if (pathbuf && pathlen > 0) 
    {
        NSData *nsBytes = [nsPath dataUsingEncoding:NSUTF8StringEncoding];
        int copyLen = (int)MIN(pathlen - 1, (int)nsBytes.length);
        xmem_copy(pathbuf, nsBytes.bytes, copyLen);
        pathbuf[copyLen] = 0;
    }

	if (filebuf && filelen > 0) 
    {
        NSData *nsBytes = [nsFile dataUsingEncoding:NSUTF8StringEncoding];
        int copyLen = (int)MIN(filelen - 1, (int)nsBytes.length);
        xmem_copy(filebuf, nsBytes.bytes, copyLen);
        filebuf[copyLen] = 0;
    }
    
	return 1;
}}

bool_t coShellGetPathName(widget_t wt, const tchar_t* defpath, bool_t createit, tchar_t* pathbuf, int pathlen)
{@autoreleasepool {
	NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.canChooseFiles = NO;
    panel.canChooseDirectories = YES;
    panel.allowsMultipleSelection = NO;
    panel.canCreateDirectories = createit ? YES : NO;
        
	if (defpath && *defpath)
    {
        panel.directoryURL = [NSURL fileURLWithPath:[NSString stringWithUTF8String:defpath]];
    }
    if ([panel runModal] != NSModalResponseOK) return 0;

    NSURL *nsUrl = panel.URL;
    if (!nsUrl) return 0;

    NSString *nsDir = nsUrl.path;
    if (pathbuf && pathlen > 0) 
    {
        NSData *nsBytes = [nsDir dataUsingEncoding:NSUTF8StringEncoding];
        int copyLen = (int)MIN(pathlen - 1, (int)nsBytes.length);
        xmem_copy(pathbuf, nsBytes.bytes, copyLen);
        pathbuf[copyLen] = 0;
    }
    
	return 1;
}}

bool_t coShellGetCurPath(tchar_t* pathbuf, int pathlen)
{@autoreleasepool {
	NSString *nsPath = [[NSFileManager defaultManager] currentDirectoryPath];
    NSData *nsBytes = [nsPath dataUsingEncoding:NSUTF8StringEncoding];

    int copyLen = (int)MIN(pathlen - 1, (int)nsBytes.length);
    if (pathbuf && pathlen > 0) 
    {
        xmem_copy(pathbuf, nsBytes.bytes, copyLen);
        pathbuf[copyLen] = 0;
        return 1;
    }
    
	return 0;
}}

bool_t coShellGetRunPath(tchar_t* pathbuf, int pathlen)
{@autoreleasepool {
	NSString *nsPath = [[NSBundle mainBundle] executablePath];
    NSString *nsDir = nsPath.stringByDeletingLastPathComponent;
    NSData *nsBytes = [nsDir dataUsingEncoding:NSUTF8StringEncoding];
    
	int copyLen = (int)MIN(pathlen - 1, (int)nsBytes.length);
    if (pathbuf && pathlen > 0) 
    {
        xmem_copy(pathbuf, nsBytes.bytes, copyLen);
        pathbuf[copyLen] = 0;
        return 1;
    }
    
	return 0;
}}

bool_t coShellGetAppPath(tchar_t* pathbuf, int pathlen)
{@autoreleasepool {
	NSString *nsPath = [[NSBundle mainBundle] bundlePath];
    NSData *nsBytes = [nsPath dataUsingEncoding:NSUTF8StringEncoding];

    int copyLen = (int)MIN(pathlen - 1, (int)nsBytes.length);
    if (pathbuf && pathlen > 0) 
    {
        xmem_copy(pathbuf, nsBytes.bytes, copyLen);
        pathbuf[copyLen] = 0;
        return 1;
    }

    return 0;
}}

bool_t coShellGetDocPath(tchar_t* pathbuf, int pathlen)
{@autoreleasepool {
	NSArray *nsTab = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *nsDoc = nsTab.firstObject ?: @"";
    NSData *nsBytes = [nsDoc dataUsingEncoding:NSUTF8StringEncoding];

    int copyLen = (int)MIN(pathlen - 1, (int)nsBytes.length);
    if (pathbuf && pathlen > 0) 
    {
        xmem_copy(pathbuf, nsBytes.bytes, copyLen);
        pathbuf[copyLen] = 0;
        return 1;
    }

    return 0;
}}

bool_t coShellGetTmpPath(tchar_t* pathbuf, int pathlen)
{@autoreleasepool {
	NSString *nsPath = NSTemporaryDirectory();
    NSData *nsBytes = [nsPath dataUsingEncoding:NSUTF8StringEncoding];

    int copyLen = (int)MIN(pathlen - 1, (int)nsBytes.length);
    if (pathbuf && pathlen > 0) 
    {
        xmem_copy(pathbuf, nsBytes.bytes, copyLen);
        pathbuf[copyLen] = 0;
        return 1;
    }

    return 0;
}}
