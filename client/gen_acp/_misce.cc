
#include "_defi.h"


dword_t next_gb2312_code(int index, byte_t* pch)
{
	if (index < 0 || index >= CODE_SIZE)
	{
		return 0;
	}

	if (pch)
	{
		pch[0] = GETLCHAR(code_gb2312_unicode[index][0]);
		pch[1] = GETHCHAR(code_gb2312_unicode[index][0]);
	}

	return 2;
}

int unicode_gb2312_size(void)
{
	return CODE_SIZE;
}

void unicode_gb2312_code(int index, unsigned short* code, unsigned short* val, unsigned short* key)
{
	if (code)
		*code = code_unicode_gb2312[index][0];
	if (val)
		*val = code_unicode_gb2312[index][1];
	if (key)
		*key = code_unicode_gb2312[index][2];
}

int gb2312_unicode_size(void)
{
	return CODE_SIZE;
}

void gb2312_unicode_code(int index, unsigned short* code, unsigned short* val, unsigned short* key)
{
	if (code)
		*code = code_gb2312_unicode[index][0];
	if (val)
		*val = code_gb2312_unicode[index][1];
	if (key)
		*key = code_gb2312_unicode[index][2];
}

static int table_unicode_seek_gb2312(unsigned short ucs, unsigned char* mbs)
{
	int min = 0;
	int max = CODE_SIZE - 1;
	int mid;

	if (ucs == BIGBOM || ucs == LITBOM)
	{
		if (mbs)
		{
			mbs[0] = ALT_CHAR;
		}
		return 1;
	}

	if (ucs >= 0x0000 && ucs <= 0x007F)
	{
		if (mbs)
		{
			mbs[0] = (unsigned char)ucs;
		}
		return 1;
	}

	while (min <= max)
	{
		mid = (min + max) / 2;
		if (ucs < code_unicode_gb2312[mid][0])
			max = mid - 1;
		else if (ucs > code_unicode_gb2312[mid][0])
			min = mid + 1;
		else
		{
			if (mbs)
			{
				mbs[0] = GETLCHAR(code_unicode_gb2312[mid][1]);
				mbs[1] = GETHCHAR(code_unicode_gb2312[mid][1]);
			}
			return 2;
		}
	}

	if (mbs)
	{
		mbs[0] = ALT_CHAR;
		mbs[1] = ALT_CHAR;
	}

	return 2;
}

int table_gb2312_seek_unicode(unsigned char* mbs, unsigned short* ucs)
{
	int min = 0;
	int max = CODE_SIZE - 1;
	int mid;
	int len;
	unsigned short ch;

	len = gb2312_sequence(*mbs);

	if (len == 1)
	{
		if (ucs)
		{
			*ucs = MAKESHORT(mbs[0], 0);
		}
		return 1;
	}

	ch = MAKESHORT(mbs[0], mbs[1]);

	while (min <= max)
	{
		mid = (min + max) / 2;
		if (ch < code_gb2312_unicode[mid][0])
			max = mid - 1;
		else if (ch > code_gb2312_unicode[mid][0])
			min = mid + 1;
		else
		{
			if (ucs)
			{
				*ucs = code_gb2312_unicode[mid][1];
			}
			return 1;
		}
	}

	if (ucs)
	{
		*ucs = ALT_CHAR;
	}
	return 1;
}

int table_unicode_seek_help(unsigned short ucs, unsigned short* hlp)
{
	int min = 0;
	int max = CODE_SIZE - 1;
	int mid;

	if (ucs >= 0x0000 && ucs <= 0x007F)
	{
		if (ucs >= L'A' && ucs <= L'Z')
		{
			if (hlp) *hlp = ucs;
		}
		else if (ucs >= L'a' && ucs <= L'z')
		{
			if (hlp) *hlp = ucs - 32;
		}
		else
			return 0;

		return 1;
	}

	while (min <= max)
	{
		mid = (min + max) / 2;
		if (ucs < code_unicode_gb2312[mid][0])
			max = mid - 1;
		else if (ucs > code_unicode_gb2312[mid][0])
			min = mid + 1;
		else
		{
			if(hlp) *hlp = code_unicode_gb2312[mid][2];
			return 1;
		}
	}

	return 0;
}

int table_gb2312_seek_help(const unsigned char* mbs, unsigned char* hlp)
{
	int min = 0;
	int max = CODE_SIZE - 1;
	int mid;
	int len;
	unsigned short ch;

	len = gb2312_sequence(*mbs);
	if (len == 1)
	{
		if (*mbs >= 0x00 && *mbs <= 0x7F)
		{
			if (*mbs >= 'A' && *mbs <= 'Z')
			{
				if (hlp) *hlp = *mbs;
			}
			else if (*mbs >= 'a' && *mbs <= 'z')
			{
				if (hlp) *hlp = *mbs - 32;
			}
			else
				return 0;

			return 1;
		}
	}

	ch = MAKESHORT(mbs[0], mbs[1]);

	while (min <= max)
	{
		mid = (min + max) / 2;
		if (ch < code_gb2312_unicode[mid][0])
			max = mid - 1;
		else if (ch > code_gb2312_unicode[mid][0])
			min = mid + 1;
		else
		{
			if(hlp) *hlp = (unsigned char)code_gb2312_unicode[mid][2];
			return 1;
		}
	}

	return 0;
}
