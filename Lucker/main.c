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

static BOOL ValidateFlagsCallback(FLAG_TYPE Type, INT Value)
{
	switch (Type)
	{
	case FT_WORKERS:
		return Value >= 0;

	case FT_PUBLIC_KEY_TYPE:
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
			wsprintfW(Buf, L"[%02u.%02u.%04u %02u:%02u:%02u:%03u]: The application crashed unexpectedly. Trying to recover...\r\n",
				Time.wDay, Time.wMonth, Time.wYear, Time.wHour, Time.wMinute, Time.wSecond, Time.wMilliseconds);

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
	PCCOMMAND_LINE_FLAG pFlags	 = NULL;
	SYSTEM_INFO			SysInfo;
	BOOL				SMT		 = FALSE;
	DWORD				dwWorkers;
	PUBLIC_KEY_TYPE		PublicKeyType;
	DWORD64				qwCycles = 0;

	pFlags = FlagsParse(Argc, pArgv, (PVALIDATE_FLAGS_ROUTINE)ValidateFlagsCallback, NULL);

	if (!pFlags || pFlags[FT_HELP].Value == ON)
	{
		FlagsPrintUsage();
		return 0;
	}

	GetNativeSystemInfo(&SysInfo);
	IsSMTEnabled(&SMT);

	if (SMT)
	{
		wprintf(L"NOTE: Simultaneous multithreading (SMT) is enabled. This means that you have half as many physical processors as logical ones.\n\n");
		SysInfo.dwNumberOfProcessors /= 2;
	}

	dwWorkers     = pFlags[FT_WORKERS].Value == 0 ? SysInfo.dwNumberOfProcessors : min((DWORD)pFlags[FT_WORKERS].Value, SysInfo.dwNumberOfProcessors);
	PublicKeyType = (PUBLIC_KEY_TYPE)pFlags[FT_PUBLIC_KEY_TYPE].Value;

	wprintf(
		L"Workers:         %u/%u\n"
		L"Public key type: %s\n"
		L"Bind to cores:   %s\n\n",
		dwWorkers, SysInfo.dwNumberOfProcessors, PublicKeyTypeToString(PublicKeyType), pFlags[FT_BIND_WORKERS].Value ? L"yes" : L"no"
	);

	// To prevent cyclical restarts, the system will only restart the application if it has been running for a minimum of 60 seconds.
	RegisterApplicationRestart(Argc == 2 ? pArgv[1] : NULL, 0);
	RegisterApplicationRecoveryCallback((APPLICATION_RECOVERY_CALLBACK)ApplicationRecoveryCallback, NULL, RECOVERY_DEFAULT_PING_INTERVAL, 0);

	if (dwWorkers)
	{
		if (g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL))
		{
			if (StartWorkers(dwWorkers, PublicKeyType, (BOOL)pFlags[FT_BIND_WORKERS].Value, SMT))
			{
				SetConsoleCtrlHandler((PHANDLER_ROUTINE)HandlerCallback, TRUE);
				wprintf(L"All workers launched. Press 'CTRL + C' to stop.\n\n");

				while (WaitForSingleObject(g_hStopEvent, SECTOMS(PRINT_INTERVAL)) == WAIT_TIMEOUT)
				{
					qwCycles = GetCycleCount();
					wprintf(L"Speed: %llu cycles/s.\n", qwCycles / PRINT_INTERVAL);
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
