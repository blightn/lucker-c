#include "flags.h"

static CCOMMAND_LINE_FLAG g_CmdLineFlags[] =
{
	{ L"-h",  L"Print help.",																																				 FT_HELP, 		  FA_NONE,   0   },
	{ L"-w",  L"Number of workers. Must be in the range [1 <= n <= cores]. 0 - select automatically.",																		 FT_WORKERS,	  FA_NUMBER, 0   },
	{ L"-c",  L"Specify the type of coordinates to be compared:\n\t\t0 - use both compressed and uncompressed;\n\t\t1 - uncompressed only;\n\t\t2 - compressed only.\n\t\t", FT_COORDINATES,  FA_NUMBER, 0   },
	{ L"-bw", L"Bind workers to cores. You can see the result in the Program manager under the Performance tab.",															 FT_BIND_WORKERS, FA_NONE,	 OFF },
};

static COMMAND_LINE_FLAG g_CmdLineFlagsParsed[ARRAYSIZE(g_CmdLineFlags)];

VOID FlagsPrintUsage(VOID)
{
	DWORD i;

	wprintf(L"Usage:\n");

	for (i = 0; i < ARRAYSIZE(g_CmdLineFlags); ++i)
	{
		wprintf(L"\t%s", g_CmdLineFlags[i].pName);

		if (g_CmdLineFlags[i].Argument == FA_NUMBER)
		{
			wprintf(L" <n> ");
		}

		wprintf(L"\t- %s", g_CmdLineFlags[i].pDescription);

		if (i)
		{
			if (g_CmdLineFlags[i].Argument == FA_NUMBER)
			{
				wprintf(L" Default: %d.", g_CmdLineFlags[i].Value);
			}
			else
				wprintf(L" Default: %s.", g_CmdLineFlags[i].Value ? L"on" : L"off");
		}

		wprintf(L"\n");
	}

	wprintf(L"\n");
}

PCCOMMAND_LINE_FLAG FlagsGetDefaults(PDWORD pdwFlagCount)
{
	if (pdwFlagCount)
	{
		*pdwFlagCount = ARRAYSIZE(g_CmdLineFlags);
	}

	return g_CmdLineFlags;
}

PCOMMAND_LINE_FLAG FlagsParse(INT Argc, WCHAR* pArgv[], PVALIDATE_FLAGS_ROUTINE pRoutine, PDWORD pdwFlagCount)
{
	INT i = 0,
		j = 0;

	if (Argc <= 1)
		return NULL;

	CopyMemory((PVOID)g_CmdLineFlagsParsed, (PCVOID)g_CmdLineFlags, sizeof(g_CmdLineFlags));

	for (i = 1; i < Argc; ++i)
	{
		for (j = 0; j < ARRAYSIZE(g_CmdLineFlagsParsed); ++j)
		{
			if (!StrCmpW(pArgv[i], g_CmdLineFlagsParsed[j].pName))
				break;
		}

		if (j == 0 || j == ARRAYSIZE(g_CmdLineFlagsParsed))
			break;

		if (g_CmdLineFlagsParsed[j].Argument != FA_NONE)
		{
			if (i + 1 == Argc)
				break;

			if (!FlagsParseArgument(&g_CmdLineFlagsParsed[j], pArgv[i + 1]))
				break;

			if (pRoutine && !pRoutine(g_CmdLineFlagsParsed[j].Type, g_CmdLineFlagsParsed[j].Value))
				break;

			++i;
		}
		else
			g_CmdLineFlagsParsed[j].Value = ON;
	}

	if (i != Argc)
	{
		if (j)
		{
			if (j < ARRAYSIZE(g_CmdLineFlagsParsed) && g_CmdLineFlagsParsed[j].Argument != FA_NONE && i + 1 != Argc)
			{
				wprintf(L"Invalid flag: %s %s\n", pArgv[i], pArgv[i + 1]);
			}
			else
				wprintf(L"Invalid flag: %s\n", pArgv[i]);

			wprintf(L"Other flags will be ignored.\n\n");
		}

		return NULL;
	}

	if (pdwFlagCount)
	{
		*pdwFlagCount = ARRAYSIZE(g_CmdLineFlagsParsed);
	}

	return g_CmdLineFlagsParsed;
}

static BOOL FlagsParseArgument(PCOMMAND_LINE_FLAG pFlag, PCWSTR pArgument)
{
	switch (pFlag->Argument)
	{
	case FA_NUMBER:
		return StrToIntExW(pArgument, STIF_SUPPORT_HEX, &pFlag->Value);
	}

	return FALSE;
}
