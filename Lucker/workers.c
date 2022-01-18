#include "workers.h"

static PCWSTR g_pCoinSymbols[] =
{
	L"BTC",
	L"ETH",
	L"LTC",
};

static COIN_DATA g_CoinData[ARRAYSIZE(g_pCoinSymbols)];

BOOL StartWorkers(DWORD dwCount)
{
	BOOL Ok = FALSE;

	if (dwCount)
	{
		Ok = LoadAddresses();
	}

	return Ok;
}

VOID StopWorkers(VOID)
{
	DWORD i;

	for (i = 0; i < ARRAYSIZE(g_CoinData) && g_CoinData[i].Coin != C_INVALID; ++i)
	{
		if (g_CoinData[i].pbAddresses)
		{
			HeapFree(GetProcessHeap(), 0, (PVOID)g_CoinData[i].pbAddresses);
		}

		ZeroMemory((PVOID)&g_CoinData[i], sizeof(g_CoinData[i]));
	}
}

DWORD64 GetCycleCount(VOID)
{


	return 15;
}

static BOOL GetDataPath(PWSTR pPath, DWORD dwSize)
{
	BOOL Ok = FALSE;

	if (GetModuleFileNameW(NULL, pPath, dwSize) < dwSize)
	{
#ifdef _DEBUG
		PathRemoveFileSpecW(pPath);
		PathRemoveFileSpecW(pPath);
		PathRemoveFileSpecW(pPath);
#endif
		if (PathRemoveFileSpecW(pPath))
		{
			Ok = SUCCEEDED(StringCchCatW(pPath, dwSize, L"\\" DATA_FOLDER L"\\"));
		}
	}

	return Ok;
}

static COIN CoinFromFileName(PCWSTR pFileName)
{
	DWORD i;

	for (i = 0; i < ARRAYSIZE(g_pCoinSymbols); ++i)
	{
		if (StrCmpNIW(pFileName, g_pCoinSymbols[i], lstrlenW(g_pCoinSymbols[i])) == 0)
			return i + 1; // Потому что "C_INVALID == 0".
	}

	return C_INVALID;
}

static PSTR ReadFileData(PCWSTR pPath, PDWORD pdwSize)
{
	HANDLE hFile  = INVALID_HANDLE_VALUE;
	DWORD  dwSize,
		   dwRead = 0;
	PSTR   pData  = NULL;

	if ((hFile = CreateFileW(pPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
	{
		if ((dwSize = GetFileSize(hFile, NULL)) != INVALID_FILE_SIZE && dwSize)
		{
			if (pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)dwSize + 1))
			{
				if (ReadFile(hFile, (PVOID)pData, dwSize, &dwRead, NULL) && dwRead == dwSize)
				{
					if (pdwSize)
					{
						*pdwSize = dwSize + 1;
					}
				}
				else
				{
					HeapFree(GetProcessHeap(), 0, (PVOID)pData);
					pData = NULL;
				}
			}
		}

		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}

	return pData;
}

static DWORD CountLines(PCSTR pData)
{
	PCSTR pLine   = pData;
	DWORD dwLines = 0;

	while (pLine = StrStrA(pLine, "\r\n"))
	{
		pLine += lstrlenA("\r\n");
		++dwLines;
	}

	return dwLines;
}

static BOOL HexToBin(BYTE bHex, PBYTE pbOut)
{
	if (bHex >= '0' && bHex <= '9')
	{
		*pbOut = bHex - '0';
	}
	else if (bHex >= 'a' && bHex <= 'f')
	{
		*pbOut = bHex - 'a' + 0xA;
	}
	else if (bHex >= 'A' && bHex <= 'F')
	{
		*pbOut = bHex - 'A' + 0xA;
	}
	else
		return FALSE;

	return TRUE;
}

// "OPENSSL_hexstr2buf()".
static BOOL HexToBinA(PCSTR pHex, PBYTE pbBuf, DWORD dwSize)
{
	DWORD dwLen,
		  i;
	BYTE  bA,
		  bB;

	if (!(dwLen = lstrlenA(pHex)) || dwLen % 2 || dwLen / 2 > dwSize)
		return FALSE;

	for (i = 0; i < dwLen; i += 2)
	{
		if (!HexToBin(pHex[i], &bA) || !HexToBin(pHex[i + 1], &bB))
			return FALSE;

		*pbBuf++ = (bA << 4) + bB;
	}

	return TRUE;
}

/*
	18Dt2hJQgjkYfGMHT8YPcGCx8hcXabWLX9
	1rH4nEXYDgwNeDq5oBp4E2aVGnpQYZrd2

	0x6fa462171a62ff5ec408e8f0841f10706a66d273
	0xa41d491d21fa13bd4df238aefcaddc0571630bc5

	LKfA8QUYDdmh3c844KLa2xByV6uGdghdRL
	LhQNq9Pm8Mj5j1tZGA1wjeZhKU11UjhvSK
*/

// Валидацию и декодирование адреса можно вынести в отдельные ф-ии (на каждую монету).
static DWORD DecodeAddress(COIN Coin, PCSTR pAddress, PBYTE pbDecoded, DWORD dwSize)
{
	DWORD dwLen;
	BOOL  Ok = FALSE;

	if (dwLen = lstrlenA(pAddress))
	{
		if (Coin == C_BTC && pAddress[0] == '1' || Coin == C_LTC && pAddress[0] == 'L')
		{
			if ((dwLen = Base58Decode(pAddress, pbDecoded/*, dwSize*/)) == DECODED_ADDRESS_SIZE + 5)
			{
				MoveMemory((PVOID)pbDecoded, (PCVOID)&pbDecoded[1], dwLen - 1);
				dwLen -= 5;
				Ok	   = TRUE;
			}
		}
		else if (Coin == C_ETH && StrCmpNIA(pAddress, "0x", lstrlenA("0x")) == 0)
		{
			if (dwLen == 42)
			{
				if (Ok = HexToBinA(&pAddress[2], pbDecoded, dwSize))
				{
					dwLen = (dwLen - 2) / 2;
				}
			}
		}
	}

	return Ok ? dwLen : 0;
}

// DECODED_ADDRESS_SIZE.
static DWORD CopyAddresses(COIN Coin, PCSTR pData, PBYTE pbAddresses)
{
	PCSTR pCRLF   = NULL;
	CHAR  Address[64]; // !
	BYTE  bDecoded[64]; // !
	DWORD dwLen,
		  dwCount = 0;

	do
	{
		if (!(pCRLF = StrStrA(pData, "\r\n")))
			break;

		StringCchCopyNA(Address, ARRAYSIZE(Address), pData, pCRLF - pData);
		StrTrimA(Address, " \t");

		// На данный момент ВСЕГДА возвращается DECODED_ADDRESS_SIZE (в таком случае можно просто возвращать BOOL).
		if ((dwLen = DecodeAddress(Coin, Address, bDecoded, ARRAYSIZE(bDecoded))) == DECODED_ADDRESS_SIZE)
		{
			CopyMemory((PVOID)pbAddresses, (PCVOID)bDecoded, dwLen);
			pbAddresses += DECODED_ADDRESS_SIZE;
			++dwCount;
		}

		pData = pCRLF + lstrlenA("\r\n");

	} while (*pData);

	return dwCount;
}

// Параметр dwSize пока не используется.
static DWORD ParseToCoinData(COIN Coin, PCSTR pData, DWORD dwLines)
{
	DWORD i;
	PBYTE pbAddresses = NULL;

	for (i = 0; i < ARRAYSIZE(g_CoinData) && g_CoinData[i].Coin != C_INVALID; ++i)
	{
		if (g_CoinData[i].Coin == Coin)
			return 0;
	}

	if (i != ARRAYSIZE(g_CoinData))
	{
		g_CoinData[i].Coin = Coin;

		if (g_CoinData[i].pbAddresses = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)dwLines * DECODED_ADDRESS_SIZE))
		{
			if (g_CoinData[i].dwAddressCount = CopyAddresses(Coin, pData, g_CoinData[i].pbAddresses))
			{
				if (g_CoinData[i].dwAddressCount != dwLines)
				{
					if (pbAddresses = (PBYTE)HeapReAlloc(GetProcessHeap(), 0, (PVOID)g_CoinData[i].pbAddresses, (SIZE_T)g_CoinData[i].dwAddressCount * DECODED_ADDRESS_SIZE))
					{
						g_CoinData[i].pbAddresses = pbAddresses;
					}
				}

				return g_CoinData[i].dwAddressCount;
			}

			HeapFree(GetProcessHeap(), 0, (PVOID)g_CoinData[i].pbAddresses);
		}

		ZeroMemory((PVOID)&g_CoinData[i], sizeof(g_CoinData[i]));
	}

	return 0;
}

// Файлы должны быть в Ansi с .txt и '\r\n' (обязательно в конце).
static BOOL LoadAddresses(VOID)
{
	WCHAR			 Path[MAX_PATH];
	WIN32_FIND_DATAW FindData;
	HANDLE			 hFind		   = INVALID_HANDLE_VALUE;
	DWORD			 dwAllFiles	   = 0,
					 dwAllLines,
					 dwLoadedLines,
					 dwLoadedFiles = 0;
	COIN			 Coin;
	PSTR			 pData		   = NULL;
	BOOL			 Ok			   = FALSE;

	wprintf(L"\nLoading files with addresses...\n");

	if (GetDataPath(Path, ARRAYSIZE(Path)))
	{
		StringCchCatW(Path, ARRAYSIZE(Path), L"\\*");
		ZeroMemory((PVOID)&FindData, sizeof(FindData));

		if ((hFind = FindFirstFileW(Path, &FindData)) != INVALID_HANDLE_VALUE)
		{
			do
			{
				if (FindData.dwFileAttributes & ~FILE_ATTRIBUTE_DIRECTORY)
				{
					++dwAllFiles;

					if ((Coin = CoinFromFileName(FindData.cFileName)) != C_INVALID)
					{
						PathRemoveFileSpecW(Path);
						StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Path, FindData.cFileName);

						if (pData = ReadFileData(Path, NULL))
						{
							if ((dwAllLines = CountLines(pData)) && (dwLoadedLines = ParseToCoinData(Coin, pData, dwAllLines)))
							{
								wprintf(L"File %s loaded: %d/%d addresses.\n", FindData.cFileName, dwLoadedLines, dwAllLines);
								++dwLoadedFiles;
							}
							else
								wprintf(L"Can't parse loaded file: %s\n", FindData.cFileName);

							HeapFree(GetProcessHeap(), 0, (PVOID)pData);
							pData = NULL;
						}
						else
							wprintf(L"Can't load file: %s\n", FindData.cFileName);
					}
					else
						wprintf(L"Coin not supported: %s\n", FindData.cFileName);
				}

			} while (FindNextFileW(hFind, &FindData));

			if (!dwAllFiles)
			{
				wprintf(L"There are no files in the " DATA_FOLDER L" folder.\n");
			}

			Ok = GetLastError() == ERROR_NO_MORE_FILES && dwLoadedFiles /*&& dwAllFiles == dwLoadedFiles*/;

			// Вывести "g_CoinData".
			/*
			{
				DWORD i;
				BYTE bBuf[512] = { 0 }; // !

				wprintf(L"\n");

				for (i = 0; i < ARRAYSIZE(g_CoinData); ++i)
				{
					wprintf(L"Coin: %d\n", g_CoinData[i].Coin);
					wprintf(L"dwAddressCount: %d\n", g_CoinData[i].dwAddressCount);
					CopyMemory((PVOID)bBuf, (PCVOID)g_CoinData[i].pbAddresses, (SIZE_T)g_CoinData[i].dwAddressCount * DECODED_ADDRESS_SIZE);
				}

				wprintf(L"\n");
			}
			//*/

			FindClose(hFind);
			hFind = INVALID_HANDLE_VALUE;
		}
		else //if (GetLastError() != ERROR_FILE_NOT_FOUND)
			wprintf(DATA_FOLDER L" folder doesn't exist.\n");
	}
	else
		wprintf(L"Can't get path to " DATA_FOLDER L" folder.\n");

	wprintf(L"%d/%d files loaded.\n\n", dwLoadedFiles, dwAllFiles);

	return Ok;
}
