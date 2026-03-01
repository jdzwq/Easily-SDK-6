/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc file system call document

	@module	_if_file.c | linux implement file

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

#include "../xdkloc.h"

#ifdef XDK_SUPPORT_FILE

res_file_t _file_open(const tchar_t* fname, dword_t fmode)
{
	int fd = 0;
    int flag = 0;

	if (fmode & FILE_OPEN_APPEND)
        flag = O_CREAT | O_RDWR | O_APPEND;
	else if(fmode & FILE_OPEN_CREATE)
		flag = O_CREAT | O_RDWR | O_TRUNC;
    else if(fmode & FILE_OPEN_WRITE)
        flag = O_RDWR;
	else
		flag = O_RDONLY;
    
    if(fmode & FILE_OPEN_OVERLAP)
        flag |= O_NONBLOCK;

    fd = open(fname, flag, S_IRWXU | S_IXGRP | S_IROTH | S_IXOTH);
    if(fd < 0)
        return INVALID_FILE;

	return (res_file_t)fd;
}

void _file_close(res_file_t fh)
{
	close(fh);
}

bool_t _file_size(res_file_t fh, vword_t* fs)
{
    struct stat st = {0};
    
    if(fstat(fh, &st) < 0) return 0;
    
    if(fs) *fs = (vword_t)(st.st_size);
    
    return 1;
}

bool_t _file_write(res_file_t fh, void* buf, dword_t size, async_t* pb)
{
    dword_t* pcb = (pb) ? &(pb->size) : NULL;
    struct timeval tv = {0};

    int rs, rt;
    struct epoll_event ev = {0};
    fd_set fs = {0};

    if (pb->type == ASYNC_QUEUE)
    {
        ev.events = EPOLLOUT;
        ev.data.fd = fh; 

        epoll_ctl(*((int*)pb->port), EPOLL_CTL_ADD, fh, &(ev));    
        rs = epoll_wait(*((int*)pb->port), &ev, 1, (int)pb->timo);
        epoll_ctl(*((int*)pb->port), EPOLL_CTL_DEL, fh, &ev); 

        if(rs < 0)
        {
            *pcb = 0;
            return 0;
        }else if(rs == 0)
        {
            *pcb = 0;
            return 1;
        }
        
        rt = (int)size;
    }
    else if (pb->type == ASYNC_EVENT)
    {
        FD_ZERO(&fs);
        FD_SET(fh, &fs);
        
        tv.tv_sec = pb->timo / 1000;
        tv.tv_usec = (pb->timo % 1000) * 1000;
        
        rs = select(fh + 1, NULL, &(fs), NULL, &tv);
        FD_CLR(fh, &fs);

        if(rs < 0)
        {
            *pcb = 0;
            return 0;
        }else if(rs == 0)
        {
            *pcb = 0;
            return 1;
        }
        
        rt = (int)size;
    }else
    {
        rt = (int)size;
    }
    
    rt = (int)write(fh, buf, rt);
    if (rt < 0)
    {
        if(errno != EINPROGRESS)
        {
            if (pcb)  *pcb = 0;
            return 0;
        }
        else
        {
            rt = 0;
        }
        
    }
    
    if (pcb) *pcb = (dword_t)rt;
    
    return 1;
}

bool_t _file_flush(res_file_t fh)
{
    return 1;
}

bool_t _file_read(res_file_t fh, void* buf, dword_t size, async_t* pb)
{
    dword_t* pcb = (pb) ? &(pb->size) : NULL;
    struct timeval tv = {0};

    int rs, rt;
    struct epoll_event ev = {0};
    fd_set fs = {0};

    if (pb->type == ASYNC_QUEUE)
    {
        ev.events = EPOLLIN;
        ev.data.fd = fh; 

        epoll_ctl(*((int*)pb->port), EPOLL_CTL_ADD, fh, &ev); 
        rs = epoll_wait(*((int*)pb->port), &ev, 1, (int)pb->timo);
        epoll_ctl(*((int*)pb->port), EPOLL_CTL_DEL, fh, &ev); 

        if(rs < 0)
        {
            *pcb = 0;
            return 0;
        }else if(rs == 0)
        {
            *pcb = 0;
            return 1;
        }
        
        if(ioctl(fh, FIONREAD, &rt) < 0)
            rt = (int)size;
        else
            rt = (rt < (int)size)? rt : (int)size;
    }
    else if (pb->type == ASYNC_EVENT)
    {
        FD_ZERO(&fs);
        FD_SET(fh, &fs);
        
        tv.tv_sec = pb->timo / 1000;
        tv.tv_usec = (pb->timo % 1000) * 1000;
        
        rs = select(fh + 1, &(fs), NULL, NULL, &tv);
        FD_CLR(fh, &fs);
        
        if(rs < 0)
        {
            *pcb = 0;
            return 0;
        }else if(rs == 0)
        {
            *pcb = 0;
            return 1;
        }
        
        if(ioctl(fh, FIONREAD, &rt) < 0)
            rt = (int)size;
        else
            rt = (rt < (int)size)? rt : (int)size;
    }else
    {
        rt = (int)size;
    }
    
    rt = (int)read(fh, buf, rt);
    if (rt < 0)
    {
        if(errno != EINPROGRESS)
        {
            if (pcb)  *pcb = 0;
            return 0;
        }
        else
        {
            rt = 0;
        }
        
    }
    
    if (pcb) *pcb = (dword_t)rt;
    
    return 1;
}

bool_t _file_read_range(res_file_t fh, vword_t off, void* buf, dword_t size)
{
    void* pBase = NULL;
    dword_t poff;
    size_t dlen, goff;

    poff = (off % PAGE_SIZE);
    goff = (off / PAGE_SIZE) * PAGE_SIZE;
    dlen = poff + size;

    pBase = mmap(NULL, dlen, PROT_READ, MAP_SHARED, fh, goff);
    if(pBase == MAP_FAILED)
    {
        return 0;
    }
    
    memcpy(buf, (void*)((char*)pBase + poff), size);
    
    munmap(pBase, dlen);
    
    return 1;
}

bool_t _file_write_range(res_file_t fh, vword_t off, void* buf, dword_t size)
{
    void* pBase = NULL;
    dword_t poff;
    size_t goff, dlen, flen = 0;
    
    _file_size(fh, (vword_t*)&flen);
    
     if(flen < (off + size))
    {
        flen = off + size;
        if(ftruncate(fh, flen) < 0)
        {
            return 0;
        }
    }
    
    poff = (off % PAGE_SIZE);
    goff = (off / PAGE_SIZE) * PAGE_SIZE;
    dlen = poff + size;
    
    pBase = mmap(NULL, dlen, PROT_WRITE | PROT_READ, MAP_SHARED, fh, goff);
    if(pBase == MAP_FAILED)
    {
        return 0;
    }
    
    memcpy((void*)((char*)pBase + poff), buf, size);
    
    msync(pBase, dlen, MS_SYNC);
    
    munmap(pBase, dlen);

    return 1;
}

void* _file_lock_range(res_file_t fh, vword_t off, dword_t size, bool_t write, res_file_t* ph)
{
    void* pBase = NULL;
    dword_t poff;
    size_t goff, dlen, flen = 0;
    int prot;

    *ph = INVALID_FILE;

    _file_size(fh, (vword_t*)&flen);
    
    //expand file first for writing
    if(flen < (off + size))
    {
        if(!write)
        {
            return NULL;
        }
        flen = off + size;
       if(ftruncate(fh, flen) < 0)
        {
            return NULL;
        }
    }
    
    poff = (off % PAGE_SIZE);
    goff = (off / PAGE_SIZE) * PAGE_SIZE;
    dlen = poff + size;
    
    prot = (write)? (PROT_WRITE | PROT_READ) : PROT_READ;
    pBase = mmap(NULL, dlen, prot, MAP_SHARED, fh, goff);
    if(pBase == MAP_FAILED)
    {
        return NULL;
    }
    
    *ph = fh;

    return (void*)((char*)pBase + poff);
}

void _file_unlock_range(res_file_t mh, vword_t off, dword_t size, void* p)
{
    void* pBase = NULL;
    dword_t poff;
    size_t goff, dlen;
    
    poff = (off % PAGE_SIZE);
    goff = (off / PAGE_SIZE) * PAGE_SIZE;
    dlen = poff + size;

    pBase = (void*)((char*)p - poff);
    
    msync(pBase, dlen, MS_ASYNC);
    
    munmap(pBase, dlen);
}


bool_t _file_truncate(res_file_t fh, vword_t off)
{
    size_t len = (size_t)off;
    
    if (ftruncate(fh, len) < 0)
        return 0;
    
    lseek(fh, len, SEEK_SET);
    
    return 1;
}

vlong_t _file_seek_begin(res_file_t fh)
{
    off_t pos;

    pos = lseek(fh, (off_t)0, SEEK_SET);

    return (vlong_t)(pos);
}

vlong_t _file_seek_end(res_file_t fh)
{
    off_t pos;

    pos = lseek(fh, (off_t)0, SEEK_END);

    return (vlong_t)(pos);
}

vlong_t _file_seek_bytes(res_file_t fh, vlong_t bytes)
{
    off_t pos;

    pos = lseek(fh, (off_t)bytes, SEEK_CUR);
    
    return (vlong_t)(pos);
}

vlong_t _file_seek_lines(res_file_t fh, vlong_t lines)
{
     unsigned char ch = 0;
    ssize_t n;
    size_t fs;
    off_t pos = 0, step = (lines > 0)? 1 : -1;

    _file_size(fh, (vword_t*)&fs);

    pos = lseek(fh, 0, SEEK_CUR);

    lines *= step;
    while(lines--)
    {
        if(step < 0)
        {
            while(ch == '\0' || ch == '\r' || ch == '\n')
            {
                pos = lseek(fh, step, SEEK_CUR);
                if(pos < 0) return (vlong_t)-1;

                n = pread(fh, &ch, 1, pos);
                if(!n) break;
            }
        }

        while(ch != '\r' && ch != '\n')
        {
            if(step < 0)
            {
                pos = lseek(fh, step, SEEK_CUR);
                if(pos < 0) return (vlong_t)-1;
            }

            n = pread(fh, &ch, 1, pos);

            if(step > 0)
            {
                pos = lseek(fh, step, SEEK_CUR);
                if(pos < 0) return (vlong_t)-1;
            }

            if(!pos || pos == fs) break;
        }

        if(ch == '\r' || ch == '\n')
        {
            pos = lseek(fh, -step, SEEK_CUR);
            if(pos < 0) return (vlong_t)-1;
        }

        if(step > 0)
        {
            while(ch == '\r' || ch == '\n')
            {
                pos = lseek(fh, step, SEEK_CUR);
                if(pos < 0) return (vlong_t)-1;

                n = pread(fh, &ch, 1, pos);
                if(!n) break;
            }
        }
    }

    return (vlong_t)(pos);
}

dword_t _file_peek_line(res_file_t fh, byte_t* buf, dword_t max)
{
    unsigned char ch = 0;
    ssize_t n;
    off_t pos;
    dword_t total = 0;

    pos = lseek(fh, 0, SEEK_CUR);
    n = pread(fh, &ch, 1, pos);
    
    while (n > 0 && ch != '\r' && ch != '\n')
    {
        if(buf && total < max) buf[total] = ch;
        total ++;

        pos ++;
        n = pread(fh, &ch, 1, pos);
    }

    while (n > 0 && (ch == '\r' || ch == '\n'))
    {
        pos ++;
        n = pread(fh, &ch, 1, pos);
    }

    return (n < 0)? 0 : total;
}

dword_t _file_read_line(res_file_t fh, byte_t* buf, dword_t max)
{
    unsigned char ch = 0;
    ssize_t n;
    off_t pos;
    dword_t total = 0;

    pos = lseek(fh, 0, SEEK_CUR);
    n = pread(fh, &ch, 1, pos);
    while (n > 0 && ch != '\r' && ch != '\n')
    {
        if(buf && total < max) buf[total] = ch;
        total ++;

        pos = lseek(fh, 1, SEEK_CUR);
        if(pos < 0) return total;

        n = pread(fh, &ch, 1, pos);
    }

    while (n > 0 && (ch == '\r' || ch == '\n'))
    {
        pos = lseek(fh, 1, SEEK_CUR);
        if(pos < 0) return total;

        n = pread(fh, &ch, 1, pos);
    }

    return (n < 0)? 0 : total;
}

dword_t _file_write_line(res_file_t fh, const byte_t* buf, dword_t len)
{
    unsigned char ch = 0;
    ssize_t n;
    dword_t total = 0;

    n = write(fh, buf, len);
    if(n < 0) return 0;
    total += n;

    ch = '\n';
    n = write(fh, &ch, 1);
    if(n < 0) return 0;
    total ++;

    return total;
}

bool_t _file_gettime(res_file_t fh, xdate_t* pdt)
{
    struct stat st = {0};
    struct tm *p;
    
    if(fstat(fh, &st) < 0)
        return 0;
    
    p = gmtime(&st.st_mtime);
    
    pdt->year = 1900 + p->tm_year;
    pdt->mon = 1 + p->tm_mon;
    pdt->day = p->tm_mday;
    pdt->hour = p->tm_hour;
    pdt->min = p->tm_min;
    pdt->sec = p->tm_sec;
    pdt->wday = p->tm_wday;
    
    return 1;
}

bool_t _file_settime(res_file_t fh, const xdate_t* pdt)
{
    struct timeval um[2] = {0};
    struct tm t = {0};
    
    t.tm_year = pdt->year - 1900;
    t.tm_mon = pdt->mon - 1;
    t.tm_mday = pdt->day;
    t.tm_hour = pdt->hour;
    t.tm_min = pdt->min;
    t.tm_sec = pdt->sec;
    
    um[0].tv_sec = um[1].tv_sec = mktime(&t);
    
    return (futimes(fh, um) < 0)? 0 : 1;
}

bool_t _file_delete(const tchar_t* fname)
{
    return (0 == remove(fname))? 1 : 0;
}

bool_t _file_info(const tchar_t* fname, file_info_t* pxf)
{
    struct stat st = {0};
    struct tm *p;
    char* token;
    
    stat(fname, &st);
    
    pxf->is_dir = S_ISDIR(st.st_mode);
    
    pxf->high_size = GETSIZEH(st.st_size);
    pxf->low_size = GETSIZEL(st.st_size);

    p = gmtime(&st.st_atime);
    
    pxf->access_time.year = 1900 + p->tm_year;
    pxf->access_time.mon = 1 + p->tm_mon;
    pxf->access_time.day = p->tm_mday;
    pxf->access_time.hour = p->tm_hour;
    pxf->access_time.min = p->tm_min;
    pxf->access_time.sec = p->tm_sec;
    pxf->access_time.wday = p->tm_wday;
    
    p = gmtime(&st.st_mtime);
    
    pxf->write_time.year = 1900 + p->tm_year;
    pxf->write_time.mon = 1 + p->tm_mon;
    pxf->write_time.day = p->tm_mday;
    pxf->write_time.hour = p->tm_hour;
    pxf->write_time.min = p->tm_min;
    pxf->write_time.sec = p->tm_sec;
    pxf->write_time.wday = p->tm_wday;
    
    p = gmtime(&st.st_ctime);
    
    pxf->create_time.year = 1900 + p->tm_year;
    pxf->create_time.mon = 1 + p->tm_mon;
    pxf->create_time.day = p->tm_mday;
    pxf->create_time.hour = p->tm_hour;
    pxf->create_time.min = p->tm_min;
    pxf->create_time.sec = p->tm_sec;
    pxf->create_time.wday = p->tm_wday;
    
    token = strchr((char*)fname, '/');
    if(token)
        strcpy(pxf->file_name, token + 1);
    else
        strcpy(pxf->file_name, fname);

	return 1;
}

bool_t _file_rename(const tchar_t* fname, const tchar_t* nname)
{
    return (0 == rename(fname, nname))? 1 : 0;
}

res_find_t _file_find_first(const tchar_t* fpath, file_info_t* pfi)
{
	DIR *pdr;
    struct dirent *dp;
    
    pdr = opendir(fpath);
    dp = readdir(pdr);
    if(!dp)
    {
        closedir(pdr);
        return (res_find_t)NULL;
    }
    
    _file_info(dp->d_name, pfi);
    
	return (res_find_t)pdr;
}

bool_t _file_find_next(res_find_t ff, file_info_t* pfi)
{
    DIR *pdr = (DIR*)ff;
    struct dirent *dp;
    
    dp = readdir(pdr);
    if(!dp)
    {
        return 0;
    }

    _file_info(dp->d_name, pfi);
    
	return 1;
}

void _file_find_close(res_find_t ff)
{
    DIR *pdr = (DIR*)ff;
    
    closedir(pdr);
}

bool_t _directory_create(const tchar_t* pname)
{
    return (mkdir(pname, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0)? 0 : 1;
}

bool_t _directory_remove(const tchar_t* pname)
{
    return (rmdir(pname) < 0)? 0 : 1;
}

bool_t	_directory_open(const tchar_t* path, dword_t mode)
{
    tchar_t cur_path[PATH_LEN];
    tchar_t* token = (tchar_t*)path;
    bool_t b_add;
    int len;
    
    b_add = ((mode & FILE_OPEN_CREATE) || (mode & FILE_OPEN_APPEND)) ? 1 : 0;
    
    while (*token == _T('\\') || *token == _T('/'))
        token++;
    
    if ((int)(token - path) == 2) //net share floder
    {
        while (*token != _T('\\') && *token != _T('/') && *token != _T('\0'))
        {
            token++;
        }
        
        if (*token == _T('\\') || *token == _T('/'))
            token++;
        
        while (*token != _T('\\') && *token != _T('/') && *token != _T('\0'))
        {
            token++;
        }
        
        if (*token == _T('\\') || *token == _T('/'))
            token++;
    }
    
    while (*token != _T('\0'))
    {
        if (b_add)
        {
            while (*token != _T('\\') && *token != _T('/') && *token != _T('\0'))
            {
                token++;
            }
        }
        else
        {
            while (*token != _T('\0'))
            {
                token++;
            }
        }
        
        len = (int)(token - path);
        strncpy(cur_path, path, len);
        cur_path[len] = _T('\0');
        
        if(access(cur_path, F_OK) < 0)
        {
            if (b_add)
            {
                if (!_directory_create(cur_path))
                    return 0;
            }
            else
            {
                return 0;
            }
        }
       
        if (*token == _T('\\') || *token == _T('/'))
            token++;
    }
    
    return 1;
}

#endif //XDK_SUPPORT_FILE