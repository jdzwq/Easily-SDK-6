
#pragma once

#include <xdk.h>

#define CODE_SIZE	7478

extern const unsigned short code_gb2312_unicode[CODE_SIZE][3];
extern const unsigned short code_unicode_gb2312[CODE_SIZE][3];

void acp_gb2312_unicode();
void acp_unicode_gb2312();

void dump_acp_gb2312();
void dump_acp_unicode();
