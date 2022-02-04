#include "main.h"

static HANDLE g_hStopEvent = NULL;

// On systems with more than 64 logical processors, the GetLogicalProcessorInformation function retrieves
// logical processor information about processors in the processor group to which the calling thread is
// currently assigned. Use the GetLogicalProcessorInformationEx function to retrieve information about
// processors in all processor groups on the system.

// wmic CPU Get NumberOfCores,NumberOfLogicalProcessors /Format:List
static BOOL IsSMTEnabled(PBOOL pEnabled)
{
	SYSTEM_INFO							  SysInfo;
	DWORD								  dwSize	= 0,
										  i,
										  dwCores;
	PSYSTEM_LOGICAL_PROCESSOR_INFORMATION pProcInfo = NULL,
										  pCurInfo	= NULL;
	BOOL								  Enabled	= FALSE,
										  Ok		= FALSE;

	ZeroMemory((PVOID)&SysInfo, sizeof(SysInfo));
	GetNativeSystemInfo(&SysInfo);

	if (!GetLogicalProcessorInformation(NULL, &dwSize) && dwSize && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		if (pProcInfo = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize))
		{
			if (GetLogicalProcessorInformation(pProcInfo, &dwSize))
			{
				for (i = dwCores = 0; i < dwSize / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION); ++i)
				{
					if (pProcInfo[i].Relationship == RelationProcessorCore)
					{
						++dwCores;
					}
				}

				if (Ok = dwCores > 0)
				{
					*pEnabled = SysInfo.dwNumberOfProcessors / 2 == dwCores;
				}
			}

			HeapFree(GetProcessHeap(), 0, (PVOID)pProcInfo);
			pProcInfo = NULL;
		}
	}

	return Ok;
}

// Те же строки в "flags.c".
static PCWSTR CoordinateTypeToString(COORDINATE_TYPE Type)
{
	switch (Type)
	{
	case CT_BOTH:		  return L"use both compressed and uncompressed";
	case CT_UNCOMPRESSED: return L"uncompressed only";
	case CT_COMPRESSED:   return L"compressed only";
	default:			  return L"ERROR";
	}
}

static BOOL ValidateFlagsCallback(FLAG_TYPE Type, INT Value)
{
	switch (Type)
	{
	case FT_WORKERS:
		return Value >= 0;

	case FT_COORDINATES:
		return Value == CT_BOTH || Value == CT_UNCOMPRESSED || Value == CT_COMPRESSED;
	}

	return FALSE;
}

static DWORD WINAPI ApplicationRecoveryCallback(PVOID pvParameter)
{
	WCHAR	   Buf[MAX_PATH];
	HANDLE	   hFile	 = INVALID_HANDLE_VALUE;
	SYSTEMTIME Time;
	DWORD	   dwSize	 = 0;
	BOOL	   Cancelled = FALSE;

	if (GetModuleFileNameW(NULL, Buf, ARRAYSIZE(Buf)))
	{
		PathRenameExtensionW(Buf, L".txt");

		if ((hFile = CreateFileW(Buf, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
		{
			GetLocalTime(&Time);
			wsprintfW(Buf, L"[%02u.%02u.%04u %02u:%02u:%02u:%03u]: ApplicationRecoveryCallback() called.\r\n", Time.wDay, Time.wMonth, Time.wYear, Time.wHour, Time.wMinute, Time.wSecond, Time.wMilliseconds);

			SetFilePointer(hFile, 0L, NULL, FILE_END);
			WriteFile(hFile, (PCVOID)Buf, lstrlenW(Buf) * sizeof(WCHAR), &dwSize, NULL);

			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
		}
	}

	ApplicationRecoveryInProgress(&Cancelled);
	ApplicationRecoveryFinished(Cancelled == FALSE);

	return 0;
}

static BOOL WINAPI HandlerCallback(DWORD dwCtrlType)
{
	if (dwCtrlType == CTRL_C_EVENT)
	{
		SetEvent(g_hStopEvent);

		return TRUE;
	}

	return FALSE;
}

INT wmain(INT Argc, WCHAR* pArgv[], WCHAR* pEnv[])
{
	ADDRESS Address    = { C_BTC, { 0x12, 0x4E, 0xF5, 0x26, 0x0C, 0x45, 0x03, 0x75, 0xA9, 0xB5, 0x6C, 0x3D, 0xF7, 0xDF, 0x75, 0x50, 0x83, 0x05, 0x30, 0xC5 } };
	BYTE	bPrivKey[] = { 0x55, 0x00, 0xa1, 0xff, 0x83, 0x78, 0xcc, 0x2c, 0x25, 0x7b, 0xcd, 0x6d, 0x3d, 0x01, 0x86, 0xac, 0x9f, 0xb9, 0xd2, 0x26, 0x15, 0x4f, 0x79, 0x3f, 0x7b, 0xcb, 0x89, 0x2e, 0xfb, 0x34, 0xeb, 0xc7 };

	SavePrivateKey_NEW(Address, bPrivKey, ARRAYSIZE(bPrivKey));

	return 0;

	PCCOMMAND_LINE_FLAG pFlags	 = NULL;
	SYSTEM_INFO			SysInfo;
	BOOL				SMT		 = FALSE;
	DWORD				dwWorkers;
	DWORD64				qwCycles = 0;

	if (!(pFlags = FlagsParse(Argc, pArgv, (PVALIDATE_FLAGS_ROUTINE)ValidateFlagsCallback, NULL)))
	{
		FlagsPrintUsage();
		wprintf(L"The auto configuring mode selected.\n\n");

		pFlags = FlagsGetDefaults(NULL);
	}

	GetNativeSystemInfo(&SysInfo);
	IsSMTEnabled(&SMT);

	if (SMT)
	{
		wprintf(L"NOTE: Simultaneous multithreading (SMT) is enabled. This means that you have half as many physical processors as logical ones.\n\n");
		SysInfo.dwNumberOfProcessors /= 2; // Сравнить "С" и "БЕЗ".
	}

	dwWorkers = pFlags[FT_WORKERS].Value == 0 ? SysInfo.dwNumberOfProcessors : min((DWORD)pFlags[FT_WORKERS].Value, SysInfo.dwNumberOfProcessors);

#ifdef _DEBUG
	//dwWorkers = 1; // !
#endif

	wprintf(L"Workers:\t%u/%u\nCoordinates:\t%s\nBind to cores:\t%s\n\n", dwWorkers, SysInfo.dwNumberOfProcessors,
		CoordinateTypeToString((COORDINATE_TYPE)pFlags[FT_COORDINATES].Value), pFlags[FT_BIND_WORKERS].Value ? L"yes" : L"no");

	// To prevent cyclical restarts, the system will only restart the application if it has been running for a minimum of 60 seconds.
	RegisterApplicationRestart(Argc == 2 ? pArgv[1] : NULL, 0);
	RegisterApplicationRecoveryCallback((APPLICATION_RECOVERY_CALLBACK)ApplicationRecoveryCallback, NULL, RECOVERY_DEFAULT_PING_INTERVAL, 0);

	if (dwWorkers)
	{
		if (g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL))
		{
			if (StartWorkers(dwWorkers, (COORDINATE_TYPE)pFlags[FT_COORDINATES].Value, (BOOL)pFlags[FT_BIND_WORKERS].Value))
			{
				SetConsoleCtrlHandler((PHANDLER_ROUTINE)HandlerCallback, TRUE);
				wprintf(L"All workers launched. Press 'CTRL + C' to stop.\n\n");

				while (WaitForSingleObject(g_hStopEvent, SECTOMS(PRINT_INTERVAL)) == WAIT_TIMEOUT)
				{
					qwCycles = GetCycleCount();
					wprintf(L"Speed: %llu cycles/s.\n", qwCycles / PRINT_INTERVAL);
					// Проверить с "Sleep(1000)" корректность подсчёта.
				}

				if (qwCycles)
				{
					wprintf(L"\n");
				}

				wprintf(L"All workers stopped.\n");
			}
			else
				wprintf(L"Workers failed to launch.\n");

			StopWorkers();

			CloseHandle(g_hStopEvent);
			g_hStopEvent = NULL;
		}
		else
			wprintf(L"Can't create stop event.\n");
	}
	else
		wprintf(L"Invalid number of workers.\n");

	wprintf(L"\n");
	system("pause");

	return 0;
}
