/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc color document

	@module	hsl.c | implement file

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

#include "clrext.h"


void rgb_to_hsl(unsigned char r, unsigned char g, unsigned char b, short* ph, short* ps, short* pl)
{
	float fr, fg, fb;
	float fh, fs, fl;
	float fmax, fmin;

	fr = (float)((float)r / 255.0);
	fg = (float)((float)g / 255.0);
	fb = (float)((float)b / 255.0);

	fmax = max(fr, max(fg, fb));
	fmin = min(fr, min(fg, fb));

	if (fmax == fmin)
	{
		fh = 0.0;
	}
	else
	{
		if (fr == fmax)
		{
			if (fg > fb)
				fh = (float)(60.0 * (fg - fb) / (fmax - fmin));
			else
				fh = (float)(60.0 * (fg - fb) / (fmax - fmin) + 360.0);
		}
		else if (fg == fmax)
		{
			fh = (float)(60.0 * (fb - fr) / (fmax - fmin) + 120.0);
		}
		else
		{
			fh = (float)(60.0 * (fr - fg) / (fmax - fmin) + 240.0);
		}

		fh = (fh > 360) ? 360 : ((fh < 0) ? 0 : fh);
	}

	fl = (float)((fmax + fmin) / 2.0);
	if (fl == 0 || fmax == fmin)
		fs = 0;
	else if (fl < 0.5)
		fs = (float)((fmax - fmin) / (fmax + fmin));
	else
		fs = (float)((fmax - fmin) / (2.0 - fmax - fmin));

	fs = (fs > 100) ? 100 : ((fs < 0) ? 0 : fs);
	fs *= 100;

	fl = (fl > 100) ? 100 : ((fl < 0) ? 0 : fl);
	fl *= 100;

	*ph = (short)fh;
	*ps = (short)fs;
	*pl = (short)fl;
}

void hsl_to_rgb(short h, short s, short l, unsigned char* pr, unsigned char* pg, unsigned char* pb)
{
	float fh, fs, fl;
	float fr, fg, fb;
	float p, q;
	float f[3];
	int i;

	fh = (float)((float)h / 360.0);
	fs = (float)((float)s / 100.0);
	fl = (float)((float)l / 100.0);

	if (fs == 0)
	{
		fr = fg = fb = (float)(fl * 255.0);
	}
	else
	{
		if (fl < 0.5)
			q = (float)(fl * (fs + 1.0));
		else
			q = fl + fs - (float)(fl * fs);

		p = (float)(fl * 2.0) - q;

		f[0] = fh + (float)(1.0 / 3.0);
		f[1] = fh;
		f[2] = fh - (float)(1.0 / 3.0);
		for (i = 0; i< 3; i++)
		{
			if (f[i] < 0)
				f[i] += 1.0;
			if (f[i] > 1)
				f[i] -= 1.0;

			if (f[i] * 6 < 1)
				f[i] = p + (float)((q - p) * 6.0 * f[i]);
			else if (f[i] * 2 < 1)
				f[i] = q;
			else if (f[i] * 3 < 2)
				f[i] = p + (float)((q - p) * ((2.0 / 3.0) - f[i]) * 6.0);
			else
				f[i] = p;
		}

		fr = (float)(f[0] * 255.0);
		fg = (float)(f[1] * 255.0);
		fb = (float)(f[2] * 255.0);
	}

	fr = (fr > 255) ? 255 : ((fr < 0) ? 0 : fr);
	fg = (fg > 255) ? 255 : ((fg < 0) ? 0 : fg);
	fb = (fb > 255) ? 255 : ((fb < 0) ? 0 : fb);

	*pr = (unsigned char)fr;
	*pg = (unsigned char)fg;
	*pb = (unsigned char)fb;
}

void lighten_rgb(int n, unsigned char* pr, unsigned char* pg, unsigned char* pb)
{
	short h, s, l;

	rgb_to_hsl(*pr, *pg, *pb, &h, &s, &l);

	l += n;

	if (l > 100)
		l = 100;
	else if (l < -100)
		l = -100;

	hsl_to_rgb(h, s, l, pr, pg, pb);
}
