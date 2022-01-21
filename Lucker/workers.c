#include "workers.h"

static const PCWSTR g_pCoinSymbols[] =
{
	L"BTC",
	L"ETH",
	L"LTC",
};

static DWORD	 g_dwWorkers;
static COIN_DATA g_CoinData[ARRAYSIZE(g_pCoinSymbols)];
static HANDLE	 g_hStopEvent = NULL;
static PHANDLE	 g_phWorkers  = NULL;

static volatile DWORD64 g_qwCycles;

BOOL StartWorkers(DWORD dwCount)
{
	DWORD i;
	BOOL  Ok = FALSE;

	if (g_dwWorkers = dwCount)
	{
		if (CryptRandomInit())
		{
			if (LoadAddresses())
			{
				if (g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL))
				{
					if (g_phWorkers = (PHANDLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, g_dwWorkers * sizeof(HANDLE)))
					{
						for (i = 0; i < g_dwWorkers; ++i)
						{
							if (!(g_phWorkers[i] = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)WorkerProc, NULL, 0, NULL)))
								break;
						}

						Ok = g_phWorkers[g_dwWorkers - 1] != NULL;
					}
					else
						wprintf(L"Can't allocate memory for worker pool.\n");
				}
				else
					wprintf(L"Can't create stop event.\n");
			}
			else
				wprintf(L"Can't load addresses.\n");
		}
		else
			wprintf(L"Can't initialize the PRNG.\n");
	}
	else
		wprintf(L"The number of workers must be positive.\n");

	return Ok;
}

VOID StopWorkers(VOID)
{
	DWORD i;

	if (g_hStopEvent)
	{
		if (g_phWorkers)
		{
			SetEvent(g_hStopEvent);
			WaitForMultipleObjects(g_dwWorkers, g_phWorkers, TRUE, WAIT_TIME);

			for (i = 0; i < g_dwWorkers; ++i)
			{
				CloseHandle(g_phWorkers[i]);
				g_phWorkers[i] = NULL;
			}

			HeapFree(GetProcessHeap(), 0, (PVOID)g_phWorkers);
			g_phWorkers = NULL;
		}

		CloseHandle(g_hStopEvent);
		g_hStopEvent = NULL;
	}

	for (i = 0; i < ARRAYSIZE(g_CoinData) && g_CoinData[i].Coin != C_INVALID; ++i)
	{
		if (g_CoinData[i].pbAddresses)
		{
			HeapFree(GetProcessHeap(), 0, (PVOID)g_CoinData[i].pbAddresses);
		}
	}

	ZeroMemory((PVOID)g_CoinData, sizeof(g_CoinData));

	if (g_dwWorkers)
	{
		CryptRandomCleanup();
	}

	g_qwCycles = g_dwWorkers = 0;
}

DWORD64 GetCycleCount(VOID)
{
	return InterlockedExchange64(&g_qwCycles, 0);
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

// Валидацию и декодирование адреса можно вынести в отдельные ф-ии (на каждую монету).
static DWORD DecodeAddress(COIN Coin, PCSTR pAddress, PBYTE pbDecoded, DWORD dwSize)
{
	DWORD dwLen;
	BOOL  Ok = FALSE;

	if (dwLen = lstrlenA(pAddress))
	{
		if (Coin == C_BTC && pAddress[0] == '1' || Coin == C_LTC && pAddress[0] == 'L')
		{
			if ((dwLen = Base58Decode(pAddress, pbDecoded, dwSize)) == 1 + DECODED_ADDRESS_SIZE + 4)
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

static DWORD ParseAddresses(COIN Coin, PCSTR pData, DWORD dwLines)
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
							if ((dwAllLines = CountLines(pData)) && (dwLoadedLines = ParseAddresses(Coin, pData, dwAllLines)))
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

			FindClose(hFind);
			hFind = INVALID_HANDLE_VALUE;
		}
		else
			wprintf(DATA_FOLDER L" folder doesn't exist.\n");
	}
	else
		wprintf(L"Can't get path to " DATA_FOLDER L" folder.\n");

	wprintf(L"%d/%d files loaded.\n\n", dwLoadedFiles, dwAllFiles);

	return Ok;
}

// Переименовать.
// Попробовать вариант с inline и сравнить производительность.
static VOID HashFromPublicKey(COIN Coin, PCBYTE pbPulicKey, DWORD dwSize, PBYTE pbHash)
{
	switch (Coin)
	{
	case C_BTC:
	case C_LTC:
		// bHash = RIPEMD160(SHA256(bPubKey))
		// Первые 20 байтов хэша.

		CryptSHA256(pbPulicKey, dwSize, pbHash);
		CryptRIPEMD160(pbHash, HASH_256_SIZE, pbHash);

		break;

	case C_ETH:
		// bHash = KECCAK256(bPubKey)
		// Последние 20 байтов хэша. Последние 20 байтов переместить в начало.

		CryptKECCAK256(&pbPulicKey[1], dwSize - 1, pbHash);
		MoveMemory((PVOID)pbHash, (PCVOID)&pbHash[HASH_256_SIZE - DECODED_ADDRESS_SIZE], DECODED_ADDRESS_SIZE);

		break;
	}
}

static VOID SavePrivateKey(COIN Coin, PCBYTE pbPrivateKey, DWORD dwSize)
{
	DWORD i;
	CHAR  Buf[256];

	Buf[0] = '\0';

	for (i = 0; i < dwSize; ++i)
	{
		if (i)
		{
			StringCchCatA(Buf, ARRAYSIZE(Buf), ", ");
		}

		StringCchPrintfA(Buf, ARRAYSIZE(Buf), "%s0x%02X", Buf, pbPrivateKey[i]);
	}

	wprintf(L"%s private key found: %S\n", g_pCoinSymbols[Coin - 1], Buf);
}

/*
Range of valid ECDSA private keys:
	- Nearly every 256-bit number is a valid ECDSA private key. Specifically, any 256-bit number from 0x1 to
		0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140 is a valid private key.
	- The range of valid private keys is governed by the secp256k1 ECDSA standard used by Bitcoin.
*/

// Попробовать один контекст на все потоки.
// Попробовать вариант с брутом только BTC и сравнить производительность.
static DWORD WINAPI WorkerProc(PVOID pvParam)
{
	PEC_CONTEXT   pCtx = NULL;
	BYTE		  bPrivKey[SECP256K1_PRIVATE_KEY_SIZE],
				  bPubKey[SECP256K1_PUBLIC_KEY_SIZE],
				  bPubKeyComp[SECP256K1_PUBLIC_KEY_COMP_SIZE],
				  bHash[HASH_256_SIZE],
				  bHashComp[HASH_256_SIZE];
	EC_PUBLIC_KEY PubKey;
	DWORD		  i,
				  j;

	if (pCtx = CryptECContextCreate(ECT_SECP256K1))
	{
		while (WaitForSingleObject(g_hStopEvent, 0) == WAIT_TIMEOUT)
		{
			// We randomize all 32 bits without checking the range, because the chance of getting a zero or
			// a value greater than 0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140
			// is very small, but much more than the chance of getting a non-empty address ;)
			if (CryptRandom(bPrivKey, sizeof(bPrivKey)))
			{
				// 5500a1ff8378cc2c257bcd6d3d0186ac9fb9d226154f793f7bcb892efb34ebc7
				//CopyMemory((PVOID)bPrivKey, (PCVOID)"\x55\x00\xa1\xff\x83\x78\xcc\x2c\x25\x7b\xcd\x6d\x3d\x01\x86\xac\x9f\xb9\xd2\x26\x15\x4f\x79\x3f\x7b\xcb\x89\x2e\xfb\x34\xeb\xc7", 32); // For debug

				if (CryptECPublicKeyFromSecret(pCtx, bPrivKey, &PubKey))
				{
					CryptECPublicKeyToBytes(pCtx, &PubKey, FALSE, bPubKey,	   sizeof(bPubKey));
					CryptECPublicKeyToBytes(pCtx, &PubKey, TRUE,  bPubKeyComp, sizeof(bPubKeyComp));

					for (i = 0; i < ARRAYSIZE(g_CoinData) && g_CoinData[i].Coin != C_INVALID; ++i)
					{
						HashFromPublicKey(g_CoinData[i].Coin, bPubKey,	   sizeof(bPubKey),		bHash);
						HashFromPublicKey(g_CoinData[i].Coin, bPubKeyComp, sizeof(bPubKeyComp), bHashComp);

						/*/
						{
							// Private key:	5500a1ff8378cc2c257bcd6d3d0186ac9fb9d226154f793f7bcb892efb34ebc7
							//
							// BTC:			00124ef5260c450375a9b56c3df7df7550830530c518610791, 0076b4e6afe774090703659ee017b08ad2e0ad6a118d73bb4e
							// LTC:			30124ef5260c450375a9b56c3df7df7550830530c5ab3a8537, 3076b4e6afe774090703659ee017b08ad2e0ad6a115795e448
							//
							// BTC:			12fokXPiUNSVvab6gxGo7Zgni2VYZS8A4x,					1BpfSsF8nQGk2718jnnrC811XxDvoqqJBf
							// ETH:			0x38e73420d07d32c789b4349988fd67a667a61892,			0x71322a0db59f5d49a04970ad26ffff00b23fe90e
							// LTC:			LLtm1jhYZ2gZBPHFs6G6PakYvErpkRqPTU,					LW3ci5Yxs4WoGuhHuvn9U94mkAbCuhyRe7

							CHAR PrivateKey[65],
								Address1[128],
								Address2[128];
							DWORD k;
							BYTE bTmp1[32],
								bTmp2[32];

							PrivateKey[0] = Address1[0] = Address2[0] = '\0';

							for (k = 0; k < sizeof(bPrivKey); ++k)
							{
								StringCchPrintfA(PrivateKey, ARRAYSIZE(PrivateKey), "%s%02x", PrivateKey, bPrivKey[k]);
							}

							switch (g_CoinData[i].Coin)
							{
							case C_BTC:
							case C_LTC:
								MoveMemory((PVOID)&bHash[1],	 (PCVOID)bHash,		DECODED_ADDRESS_SIZE);
								MoveMemory((PVOID)&bHashComp[1], (PCVOID)bHashComp, DECODED_ADDRESS_SIZE);

								bHash[0] = bHashComp[0] = g_CoinData[i].Coin == C_BTC ? 0x00 : 0x30;

								CryptSHA256(bHash,	   1 + DECODED_ADDRESS_SIZE, bTmp1);
								CryptSHA256(bHashComp, 1 + DECODED_ADDRESS_SIZE, bTmp2);

								CryptSHA256(bTmp1, HASH_256_SIZE, bTmp1);
								CryptSHA256(bTmp2, HASH_256_SIZE, bTmp2);

								CopyMemory((PVOID)&bHash	[1 + DECODED_ADDRESS_SIZE],	(PCVOID)bTmp1, 4);
								CopyMemory((PVOID)&bHashComp[1 + DECODED_ADDRESS_SIZE], (PCVOID)bTmp2, 4);

								// Для удобства конвертирования в Base58 - https://appdevtools.com/base58-encoder-decoder
								for (k = 0; k < 1 + DECODED_ADDRESS_SIZE + 4; ++k)
								{
									StringCchPrintfA(Address1, ARRAYSIZE(Address1), "%s%02x", Address1, bHash[k]);
									StringCchPrintfA(Address2, ARRAYSIZE(Address2), "%s%02x", Address2, bHashComp[k]);
								}

								StringCchCopyA(Address1, ARRAYSIZE(Address1), "12fokXPiUNSVvab6gxGo7Zgni2VYZS8A4x"); // Base58.
								StringCchCopyA(Address2, ARRAYSIZE(Address2), "1BpfSsF8nQGk2718jnnrC811XxDvoqqJBf"); // Base58.
								break;

							case C_ETH:
								StringCchCopyA(Address1, ARRAYSIZE(Address1), "0x");
								StringCchCopyA(Address2, ARRAYSIZE(Address2), "0x");

								for (k = 0; k < DECODED_ADDRESS_SIZE; ++k)
								{
									StringCchPrintfA(Address1, ARRAYSIZE(Address1), "%s%02x", Address1, bHash[k]);
									StringCchPrintfA(Address2, ARRAYSIZE(Address2), "%s%02x", Address2, bHashComp[k]);
								}
								break;
							}

							Sleep(0);
						}
						//*/

						for (j = 0; j < g_CoinData[i].dwAddressCount; ++j)
						{
							if (memcmp((PCVOID)bHash,	  (PCVOID)&g_CoinData[i].pbAddresses[j * DECODED_ADDRESS_SIZE], DECODED_ADDRESS_SIZE) == 0 ||
								memcmp((PCVOID)bHashComp, (PCVOID)&g_CoinData[i].pbAddresses[j * DECODED_ADDRESS_SIZE], DECODED_ADDRESS_SIZE) == 0)
							{
								SavePrivateKey(g_CoinData[i].Coin, bPrivKey, sizeof(bPrivKey));
							}
						}
					}
				}
			}

			InterlockedAdd64(&g_qwCycles, 1);
			//InterlockedAdd64(&g_qwCycles, LOOP_ITERATIONS);
		}

		CryptECContextDestroy(pCtx);
		pCtx = NULL;
	}

	return 0;
}
