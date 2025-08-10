
#include <xdk.h>
#include <xdg.h>
#include <xdu.h>


glyph_info_t ascii_medium_regular_list[16] = {
	{_T("EN-ARI-M-R-5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-M-R-5.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("5.5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-M-R-6.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("6.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-R-7.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("7.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-R-9"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("9"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-R-10.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("10.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-R-12"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("12"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-R-14"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("14"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-R-15"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("15"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-R-16"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("16"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-R-18"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("18"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-R-22"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("22"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-M-R-24"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("24"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-M-R-26"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("26"), 40, 40, 40, 0, 0x20, 0x20, 223, 5, NULL, NULL },
	{_T("EN-ARI-M-R-36"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("36"), 48, 48, 48, 0, 0x20, 0x20, 223, 6, NULL, NULL },
	{_T("EN-ARI-M-R-42"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("42"), 56, 56, 56, 0, 0x20, 0x20, 223, 7, NULL, NULL }
};
glyph_info_t ascii_bold_regular_list[16] = {
	{_T("EN-ARI-B-R-5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-B-R-5.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("5.5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-B-R-6.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("6.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-R-7.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("7.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-R-9"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("9"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-R-10.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("10.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-R-12"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("12"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-R-14"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("14"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-R-15"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("15"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-R-16"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("16"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-R-18"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("18"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-R-22"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("22"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-B-R-24"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("24"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-B-R-26"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("26"), 40, 40, 40, 0, 0x20, 0x20, 223, 5, NULL, NULL },
	{_T("EN-ARI-B-R-36"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("36"), 48, 48, 48, 0, 0x20, 0x20, 223, 6, NULL, NULL },
	{_T("EN-ARI-B-R-42"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("42"), 56, 56, 56, 0, 0x20, 0x20, 223, 7, NULL, NULL }
};
glyph_info_t ascii_medium_italic_list[16] = {
	{_T("EN-ARI-M-I-5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-M-I-5.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("5.5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-M-I-6.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("6.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-I-7.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("7.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-I-9"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("9"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-I-10.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("10.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-I-12"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("12"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-I-14"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("14"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-I-15"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("15"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-I-16"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("16"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-I-18"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("18"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-I-22"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("22"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-M-I-24"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("24"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-M-I-26"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("26"), 40, 40, 40, 0, 0x20, 0x20, 223, 5, NULL, NULL },
	{_T("EN-ARI-M-I-36"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("36"), 48, 48, 48, 0, 0x20, 0x20, 223, 6, NULL, NULL },
	{_T("EN-ARI-M-I-42"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("42"), 56, 56, 56, 0, 0x20, 0x20, 223, 7, NULL, NULL }
};
glyph_info_t ascii_bold_italic_list[16] = {
	{_T("EN-ARI-B-I-5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-B-I-5.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("5.5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-B-I-6.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("6.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-I-7.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("7.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-I-9"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("9"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-I-10.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("10.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-I-12"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("12"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-I-14"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("14"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-I-15"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("15"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-I-16"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("16"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-I-18"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("18"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-I-22"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("22"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-B-I-24"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("24"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-B-I-26"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("26"), 40, 40, 40, 0, 0x20, 0x20, 223, 5, NULL, NULL },
	{_T("EN-ARI-B-I-36"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("36"), 48, 48, 48, 0, 0x20, 0x20, 223, 6, NULL, NULL },
	{_T("EN-ARI-B-I-42"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("42"), 56, 56, 56, 0, 0x20, 0x20, 223, 7, NULL, NULL },
};

glyph_info_t gb2312_medium_regular_list[16] = {
	{_T("CN-ARI-M-R-5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-5.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("5.5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-6.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("6.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-7.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("7.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-9"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("9"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-10.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("10.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-12"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("12"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-14"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("14"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-15"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("15"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-16"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("16"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-18"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("18"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-22"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("22"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-24"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("24"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-26"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("26"), 40, 40, 40, 0, 0xA1A1, 0xA1A1, 8836, 5, NULL, NULL },
	{_T("CN-ARI-M-R-36"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("36"), 48, 48, 48, 0, 0xA1A1, 0xA1A1, 8836, 6, NULL, NULL },
	{_T("CN-ARI-M-R-42"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("42"), 56, 56, 56, 0, 0xA1A1, 0xA1A1, 8836, 7, NULL, NULL }
};

glyph_info_t gb2312_bold_regular_list[16] = {
	{_T("CN-ARI-M-R-5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-5.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("5.5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-6.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("6.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-7.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("7.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-9"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("9"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-10.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("10.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-12"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("12"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-14"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("14"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-15"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("15"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-16"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("16"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-18"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("18"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-22"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("22"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-24"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("24"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-26"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("26"), 40, 40, 40, 0, 0xA1A1, 0xA1A1, 8836, 5, NULL, NULL },
	{_T("CN-ARI-M-R-36"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("36"), 48, 48, 48, 0, 0xA1A1, 0xA1A1, 8836, 6, NULL, NULL },
	{_T("CN-ARI-M-R-42"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("42"), 56, 56, 56, 0, 0xA1A1, 0xA1A1, 8836, 7, NULL, NULL }
};

glyph_info_t gb2312_medium_italic_list[16] = {
	{_T("CN-ARI-M-R-5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-5.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("5.5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-6.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("6.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-7.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("7.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-9"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("9"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-10.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("10.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-12"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("12"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-14"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("14"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-15"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("15"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-16"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("16"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-18"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("18"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-22"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("22"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-24"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("24"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-26"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("26"), 40, 40, 40, 0, 0xA1A1, 0xA1A1, 8836, 5, NULL, NULL },
	{_T("CN-ARI-M-R-36"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("36"), 48, 48, 48, 0, 0xA1A1, 0xA1A1, 8836, 6, NULL, NULL },
	{_T("CN-ARI-M-R-42"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("42"), 56, 56, 56, 0, 0xA1A1, 0xA1A1, 8836, 7, NULL, NULL }
};

glyph_info_t gb2312_bold_italic_list[16] = {
	{_T("CN-ARI-M-R-5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-5.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("5.5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-6.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("6.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-7.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("7.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-9"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("9"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-10.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("10.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-12"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("12"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-14"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("14"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-15"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("15"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-16"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("16"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-18"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("18"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-22"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("22"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-24"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("24"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-26"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("26"), 40, 40, 40, 0, 0xA1A1, 0xA1A1, 8836, 5, NULL, NULL },
	{_T("CN-ARI-M-R-36"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("36"), 48, 48, 48, 0, 0xA1A1, 0xA1A1, 8836, 6, NULL, NULL },
	{_T("CN-ARI-M-R-42"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("42"), 56, 56, 56, 0, 0xA1A1, 0xA1A1, 8836, 7, NULL, NULL },
};

glyph_info_t unicode_medium_regular_list[16] = {
	{_T("CN-ARI-M-R-5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-M-R-5.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("5.5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-M-R-6.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("6.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-R-7.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("7.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-R-9"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("9"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-R-10.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("10.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-R-12"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("12"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-R-14"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("14"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-R-15"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("15"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-R-16"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("16"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-R-18"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("18"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-R-22"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("22"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-M-R-24"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("24"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-M-R-26"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("26"), 40, 40, 40, 0, 0x4E00, 0x20, 20902, 5, NULL, NULL },
	{_T("CN-ARI-M-R-36"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("36"), 48, 48, 48, 0, 0x4E00, 0x20, 20902, 6, NULL, NULL },
	{_T("CN-ARI-M-R-42"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("42"), 56, 56, 56, 0, 0x4E00, 0x20, 20902, 7, NULL, NULL }
};

glyph_info_t unicode_bold_regular_list[16] = {
	{_T("CN-ARI-B-R-5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-B-R-5.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("5.5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-B-R-6.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("6.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-R-7.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("7.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-R-9"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("9"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-R-10.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("10.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-R-12"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("12"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-R-14"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("14"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-R-15"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("15"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-R-16"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("16"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-R-18"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("18"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-R-22"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("22"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-B-R-24"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("24"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-B-R-26"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("26"), 40, 40, 40, 0, 0x4E00, 0x20, 20902, 5, NULL, NULL },
	{_T("CN-ARI-B-R-36"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("36"), 48, 48, 48, 0, 0x4E00, 0x20, 20902, 6, NULL, NULL },
	{_T("CN-ARI-B-R-42"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("42"), 56, 56, 56, 0, 0x4E00, 0x20, 20902, 7, NULL, NULL }
};

glyph_info_t unicode_medium_italic_list[16] = {
	{_T("CN-ARI-M-I-5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-M-I-5.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("5.5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-M-I-6.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("6.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-I-7.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("7.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-I-9"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("9"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-I-10.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("10.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-I-12"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("12"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-I-14"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("14"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-I-15"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("15"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-I-16"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("16"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-I-18"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("18"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-I-22"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("22"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-M-I-24"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("24"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-M-I-26"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("26"), 40, 40, 40, 0, 0x4E00, 0x20, 20902, 5, NULL, NULL },
	{_T("CN-ARI-M-I-36"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("36"), 48, 48, 48, 0, 0x4E00, 0x20, 20902, 6, NULL, NULL },
	{_T("CN-ARI-M-I-42"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("42"), 56, 56, 56, 0, 0x4E00, 0x20, 20902, 7, NULL, NULL }
};

glyph_info_t unicode_bold_italic_list[16] = {
	{_T("CN-ARI-B-I-5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-B-I-5.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("5.5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-B-I-6.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("6.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-I-7.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("7.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-I-9"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("9"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-I-10.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("10.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-I-12"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("12"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-I-14"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("14"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-I-15"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("15"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-I-16"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("16"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-I-18"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("18"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-I-22"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("22"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-B-I-24"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("24"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-B-I-26"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("26"), 40, 40, 40, 0, 0x4E00, 0x20, 20902, 5, NULL, NULL },
	{_T("CN-ARI-B-I-36"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("36"), 48, 48, 48, 0, 0x4E00, 0x20, 20902, 6, NULL, NULL },
	{_T("CN-ARI-B-I-42"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("42"), 56, 56, 56, 0, 0x4E00, 0x20, 20902, 7, NULL, NULL },
};

static const unsigned char bitmask[8] = { 0x7f, 0xbf, 0xdf, 0xef, 0xf7, 0xfb, 0xfd, 0xfe };

if_context_t if_context = {0};

void gen_glyph(visual_t vc, glyph_info_t* pgi)
{
	visual_t vc_mem;
	byte_t pch[UTF_LEN + 1] = { 0 };
	tchar_t str[CHS_LEN + 1] = { 0 };
 
	xfont_t xf;
	default_xfont(&xf);
	xscpy(xf.color, GDI_ATTR_RGB_WHITE);

	tchar_t ch;
	dword_t dw;
	tchar_t fname[PATH_LEN];

	int i;

	for (i = 0; i < 16; i++)
	{
		ch = pgi[i].charset[0];

		xsprintf(fname, _T("%s-%s-%s-%s-%s.gly"),
			pgi[i].charset,
			pgi[i].family,
			pgi[i].weight,
			pgi[i].style,
			pgi[i].size);

		xfont_from_glyph_info(&xf, &pgi[i]);

		xhand_t unf = xuncf_open_file(NULL, fname, FILE_OPEN_CREATE);

		tchar_t title[1024] = { 0 };
		byte_t utf_buf[1024] = { 0 };

		int n;
		n = xsprintf(title, _T("%s,%d,%d,%d,%s,%s,%s,%s\n"), 
			pgi[i].charset, 
			pgi[i].characters, 
			pgi[i].width, 
			pgi[i].height, 
			pgi[i].family, 
			pgi[i].weight, 
			pgi[i].style, 
			pgi[i].size);

#if defined(_UNICODE) || defined(UNICODE)
		dw = ucs_to_utf8(title, n, utf_buf, 1024);
#else
		dw = mbs_to_utf8(title, n, utf_buf, 1024);
#endif
		utf_buf[dw] = '\0';

		xuncf_write_file(unf, utf_buf, &dw);

		printf((char*)utf_buf);
		printf("\n");

		int w, h;
		w = pgi[i].width;
		h = pgi[i].height;

		byte_t* bmp_buf = (byte_t*)xmem_alloc(pgi[i].bytesperline * h);

		xsize_t xs;
		xpoint_t pt;
		int k, j;
		xcolor_t xc;
		wchar_t wc;
		int rt, ft_size;

		ft_size = xstol(pgi[i].size);

		if (ch == _T('A'))
		{
			pch[0] = 0x00;
			pch[1] = (byte_t)pgi[i].firstchar;
		}
		else
		{
			//save as big endian bytes
			pch[0] = LIT_GETHBYTE(pgi[i].firstchar);
			pch[1] = LIT_GETLBYTE(pgi[i].firstchar);
		}

		do
		{
			wc = 0;
			if (ch == _T('G'))
			{
				gb2312_byte_to_ucs(pch, &wc);
			}else
			{
				//restore from big endian bytes
				wc = BIG_MAKESWORD(pch[0], pch[1]);
			}

			vc_mem = (*if_context.pf_create_compatible_context)(vc, w, h);

			(*if_context.pf_gdi_text_size)(vc_mem, &xf, &wc, 1, &xs);

			if (ch == _T('A'))
				xsprintf(title, _T("0x%02X,%d,%d\n"), pch[1], xs.w, xs.h);
			else
				xsprintf(title, _T("0x%02X%02X,%d,%d\n"), pch[0], pch[1], xs.w, xs.h);

#if defined(_UNICODE) || defined(UNICODE)
			dw = ucs_to_utf8(title, -1, utf_buf, 1024);
#else
			dw = mbs_to_utf8(title, -1, utf_buf, 1024);
#endif

			xuncf_write_file(unf, utf_buf, &dw);

			pt.x = 0;
			pt.y = 0;
			(*if_context.pf_gdi_text_out)(vc_mem, &xf, &pt, &wc, 1);
			
			xmem_zero(bmp_buf, pgi[i].bytesperline * h);

			k = 0;
			xs.w = (xs.w < w) ? xs.w : w;
			xs.h = (xs.h < h) ? xs.h : h;
			pt.y = 0;
			while (pt.y < xs.h)
			{
				pt.x = 0;
				while (pt.x < xs.w)
				{
					(*if_context.pf_gdi_get_point)(vc_mem, &xc, &pt);

					j = k * pgi[i].bytesperline + pt.x / 8;
					n = pt.x % 8;

					if (xc.r | xc.g | xc.b)
						bmp_buf[j] |= ~bitmask[n];
					else
						bmp_buf[j] &= bitmask[n];
		
					pt.x++;
				}
				k++;
				pt.y++;
			}

			(*if_context.pf_destroy_context)(vc_mem);

			n = pgi[i].bytesperline;
			for (k = 0; k < h; k++)
			{
				xmem_zero(utf_buf, 1024);

				for (j = 0; j < n; j++)
				{
					a_xsappend((schar_t*)utf_buf, "%#02X", bmp_buf[k * n + j]);

					if (j == n - 1)
						a_xscat((schar_t*)utf_buf, "\n");
					else
						a_xscat((schar_t*)utf_buf, " ");
				}

				dw = a_xslen((schar_t*)utf_buf);
				xuncf_write_file(unf, utf_buf, &dw);
			}

			if (ch == _T('A'))
				acp_next_ascii_char(pch);
			else if (ch == _T('G'))
				acp_next_gb2312_char(pch);
			else
				acp_next_unicode_char(pch);

		} while (pch[0] || pch[1]);

		xmem_free(bmp_buf);

		xuncf_close_file(unf);
	}
}

/********************************************************************************/

#if defined(WINDOWS)
#pragma comment( linker, "/subsystem:windows /entry:mainCRTStartup" )
#endif

int main(int argc, const char * argv[]) {

    xdk_process_init(XDK_APARTMENT_PROCESS);
	
	xdu_impl_context(&if_context);

	xdu_impl_context_graphic(&if_context);

	xdu_impl_context_bitmap(&if_context);

	(*if_context.pf_context_startup)();

	visual_t vc;

	vc = (*if_context.pf_create_display_context)(NULL);
	gen_glyph(vc, ascii_medium_regular_list);
	(*if_context.pf_destroy_context)(vc);

	vc = (*if_context.pf_create_display_context)(NULL);
	gen_glyph(vc, ascii_bold_regular_list);
	(*if_context.pf_destroy_context)(vc);

	vc = (*if_context.pf_create_display_context)(NULL);
	gen_glyph(vc, ascii_medium_italic_list);
	(*if_context.pf_destroy_context)(vc);

	vc = (*if_context.pf_create_display_context)(NULL);
	gen_glyph(vc, ascii_bold_italic_list);
	(*if_context.pf_destroy_context)(vc);

	vc = (*if_context.pf_create_display_context)(NULL);
	gen_glyph(vc, gb2312_medium_regular_list);
	(*if_context.pf_destroy_context)(vc);

	vc = (*if_context.pf_create_display_context)(NULL);
	gen_glyph(vc, gb2312_bold_regular_list);
	(*if_context.pf_destroy_context)(vc);

	vc = (*if_context.pf_create_display_context)(NULL);
	gen_glyph(vc, gb2312_medium_italic_list);
	(*if_context.pf_destroy_context)(vc);

	vc = (*if_context.pf_create_display_context)(NULL);
	gen_glyph(vc, gb2312_bold_italic_list);
	(*if_context.pf_destroy_context)(vc);

	/*vc = (*if_context.pf_create_display_context)(NULL);
	gen_glyph(vc, unicode_medium_regular_list);
	(*if_context.pf_destroy_context)(vc);

	vc = (*if_context.pf_create_display_context)(NULL);
	gen_glyph(vc, unicode_bold_regular_list);
	(*if_context.pf_destroy_context)(vc);

	vc = (*if_context.pf_create_display_context)(NULL);
	gen_glyph(vc, unicode_medium_italic_list);
	(*if_context.pf_destroy_context)(vc);

	vc = (*if_context.pf_create_display_context)(NULL);
	gen_glyph(vc, unicode_bold_italic_list);
	(*if_context.pf_destroy_context)(vc);*/
	
	(*if_context.pf_context_cleanup)();

    xdk_process_uninit();

    return 0;
}
