#include "main.h"

static HANDLE g_hStopEvent = NULL;

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

static BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
{
	if (dwCtrlType == CTRL_C_EVENT)
	{
		SetEvent(g_hStopEvent);

		return TRUE;
	}

	return FALSE;
}

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

INT wmain(INT Argc, WCHAR* pArgv[], WCHAR* pEnv[])
{
	SYSTEM_INFO SysInfo;
	DWORD		dwThreads = 0;
	BOOL		SMT		  = FALSE;
	DWORD64		qwCycles  = 0;

	// To prevent cyclical restarts, the system will only restart the application if it has been running for a minimum of 60 seconds.
	RegisterApplicationRestart(Argc == 2 ? pArgv[1] : NULL, 0);
	RegisterApplicationRecoveryCallback((APPLICATION_RECOVERY_CALLBACK)ApplicationRecoveryCallback, NULL, RECOVERY_DEFAULT_PING_INTERVAL, 0);

	GetNativeSystemInfo(&SysInfo);
	IsSMTEnabled(&SMT);

	// Проверить форматирование во ВСЕХ 3-х случаях (да и везде тоже).
	if (Argc == 1)
	{
		wprintf(L"The auto configuring mode selected. You can also enter the number of threads (cores) to use via the command line: prog.exe [1 <= threads <= %u]\n", SysInfo.dwNumberOfProcessors);
		dwThreads = SysInfo.dwNumberOfProcessors;

		if (SMT)
		{
			dwThreads /= 2;
		}
	}
	else if (Argc == 2 && StrToIntExW(pArgv[1], STIF_DEFAULT, (PINT)&dwThreads) && dwThreads)
	{
		dwThreads = min(dwThreads, SysInfo.dwNumberOfProcessors);
	}
	else
		wprintf(L"Improper usage. Options:\n\t1. prog.exe\n\t2: prog.exe [1 <= threads <= %u]\n", SysInfo.dwNumberOfProcessors);

	wprintf(L"\n");

	if (SMT)
	{
		wprintf(L"NOTE: Simultaneous multithreading (SMT) is enabled. This means that you have half as many physical processors as logical ones.\n");
	}

	if (dwThreads)
	{
		if (g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL))
		{
			wprintf(L"%u/%u threads (cores) will be used.\n", dwThreads, SysInfo.dwNumberOfProcessors);

			if (StartWorkers(dwThreads))
			{
				SetConsoleCtrlHandler((PHANDLER_ROUTINE)HandlerRoutine, TRUE);
				wprintf(L"All threads launched. Press 'CTRL + C' to stop.\n\n");

				while (WaitForSingleObject(g_hStopEvent, SECTOMS(PRINT_INTERVAL)) == WAIT_TIMEOUT)
				{
					qwCycles = GetCycleCount();
					wprintf(L"Speed: %llu cycles/s.\n", qwCycles / PRINT_INTERVAL);
					// Проверить с "Sleep(1000)" корректность подсчёта.
				}

				StopWorkers();

				if (qwCycles)
				{
					wprintf(L"\n");
				}

				wprintf(L"All threads stopped.\n");
			}
			else
				wprintf(L"Threads failed to launch.\n");

			CloseHandle(g_hStopEvent);
			g_hStopEvent = NULL;
		}
		else
			wprintf(L"Can't create stop event.\n");
	}
	else
		wprintf(L"The number of threads must be greater than zero.\n");

	wprintf(L"\n");
	system("pause");

	return 0;
}
