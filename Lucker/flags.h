#ifndef _FLAG_H_
#define _FLAG_H_

#include "defines.h"

#define OFF (FALSE)
#define ON	(TRUE)

typedef enum {
	FT_HELP,
	FT_WORKERS,
	FT_COORDINATES,
	FT_BIND_WORKERS,
} FLAG_TYPE;

typedef enum {
	FA_NONE,
	FA_NUMBER,
} FLAG_ARGUMENT;

typedef struct {
	PCWSTR		  pName;
	PCWSTR		  pDescription;
	FLAG_TYPE	  Type;
	FLAG_ARGUMENT Argument;
	INT			  Value;
} COMMAND_LINE_FLAG, *PCOMMAND_LINE_FLAG;

typedef const COMMAND_LINE_FLAG  CCOMMAND_LINE_FLAG;
typedef const COMMAND_LINE_FLAG* PCCOMMAND_LINE_FLAG;

typedef BOOL(*PVALIDATE_FLAGS_ROUTINE)(FLAG_TYPE Type, INT Value);

VOID FlagsPrintUsage(VOID);
PCOMMAND_LINE_FLAG FlagsParse(INT Argc, WCHAR* pArgv[], PVALIDATE_FLAGS_ROUTINE pRoutine, PDWORD pdwFlagCount);

static BOOL FlagsParseArgument(PCOMMAND_LINE_FLAG pFlag, PCWSTR pArgument);

#endif // _FLAG_H_
