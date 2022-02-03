#ifndef _FLAG_H_
#define _FLAG_H_

#include "defines.h" // Выше не должно быть включений с "Windows.h", чтобы не перекрывать WIN32_LEAN_AND_MEAN.

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

typedef enum {
	CT_BOTH,
	CT_UNCOMPRESSED,
	CT_COMPRESSED,
} COORDINATE_TYPE;

typedef struct {
	PCWSTR		  pName;
	PCWSTR		  pDescription;
	FLAG_TYPE	  Type;
	FLAG_ARGUMENT Argument;
	INT			  Value;
} COMMAND_LINE_FLAG, *PCOMMAND_LINE_FLAG;

typedef const COMMAND_LINE_FLAG  CCOMMAND_LINE_FLAG;
typedef const COMMAND_LINE_FLAG* PCCOMMAND_LINE_FLAG;

VOID FlagsPrintUsage(VOID);
PCCOMMAND_LINE_FLAG FlagsGetDefaults(PDWORD pdwFlagCount);
PCOMMAND_LINE_FLAG FlagsParse(INT Argc, WCHAR* pArgv[], PDWORD pdwFlagCount);

static BOOL FlagsParseArgument(PCOMMAND_LINE_FLAG pFlag, PCWSTR pArgument);

#endif // _FLAG_H_
