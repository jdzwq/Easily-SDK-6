
#ifndef _RTFDECL_H
#define _RTFDECL_H

#include "../tp_def.h"

#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif
// RTF parser declarations

OEM_EXP_API int ecRtfParse(FILE *fp);
OEM_EXP_API int ecPushRtfState(void);
OEM_EXP_API int ecPopRtfState(void);
OEM_EXP_API int ecParseRtfKeyword(FILE *fp);
OEM_EXP_API int ecParseChar(int c);
OEM_EXP_API int ecTranslateKeyword(char *szKeyword, int param, int fParam);
OEM_EXP_API int ecPrintChar(int ch);
OEM_EXP_API int ecEndGroupAction(RDS rds);
OEM_EXP_API int ecApplyPropChange(IPROP iprop, int val);
OEM_EXP_API int ecChangeDest(IDEST idest);
OEM_EXP_API int ecParseSpecialKeyword(IPFN ipfn);
OEM_EXP_API int ecParseSpecialProperty(IPROP iprop, int val);
OEM_EXP_API int ecParseHexByte(void);

// RTF variable declarations

extern int cGroup;
extern RDS rds;
extern RIS ris;

extern CHP chp;
extern PAP pap;
extern SEP sep;
extern DOP dop;

extern SAVE *psave;
extern long cbBin;
extern long lParam;
extern int fSkipDestIfUnk;
extern FILE *fpIn;

#ifdef	__cplusplus
}
#endif

// RTF parser error codes

#define ecOK 0                      // Everything's fine!
#define ecStackUnderflow    1       // Unmatched '}'
#define ecStackOverflow     2       // Too many '{' -- memory exhausted
#define ecUnmatchedBrace    3       // RTF ended during an open group.
#define ecInvalidHex        4       // invalid hex character found in data
#define ecBadTable          5       // RTF table (sym or prop) invalid
#define ecAssertion         6       // Assertion failure
#define ecEndOfFile         7       // End of file reached while reading RTF

#endif /*_RTFDECL_H*/
