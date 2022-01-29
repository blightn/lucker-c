#include "workers.h"

static const COIN_SYMBOL g_CoinSymbols[] =
{
	{ C_BTC, L"BTC" },
	{ C_ETH, L"ETH" },
	{ C_LTC, L"LTC" },
};

// Ќе используетс€.
static const NETWORK_PREFIX g_NetworkPrefixes[] =
{
	{ { 0x00, 0x00 }, 1 }, // BTC
	{ {  '0',  'x' }, 2 }, // ETH
	{ { 0x30, 0x00 }, 1 }, // LTC
};

static DWORD		  g_dwWorkers;
static ALGORITHM_DATA g_AlgorithmData[A_COUNT];
static HANDLE		  g_hStopEvent = NULL;
static PHANDLE		  g_phWorkers  = NULL;

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

	for (i = 0; i < ARRAYSIZE(g_AlgorithmData); ++i)
	{
		if (g_AlgorithmData[i].pAddresses)
		{
			HeapFree(GetProcessHeap(), 0, (PVOID)g_AlgorithmData[i].pAddresses);
		}
	}

	ZeroMemory((PVOID)g_AlgorithmData, sizeof(g_AlgorithmData));

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

// TODO: MMF.
static PSTR ReadFileData(PCWSTR pPath, PSIZE_T pSize)
{
	HANDLE		  hFile  = INVALID_HANDLE_VALUE;
	LARGE_INTEGER liSize,
				  liTmp;
	PSTR		  pData  = NULL,
				  pTmp	 = NULL;
	DWORD		  dwRead = 0;

	if ((hFile = CreateFileW(pPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL)) != INVALID_HANDLE_VALUE)
	{
		if (GetFileSizeEx(hFile, &liSize) && liSize.QuadPart)
		{
			if (pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, liSize.QuadPart + 1)) // +1 for '\0'.
			{
				pTmp  = pData;
				liTmp = liSize;

				while (liTmp.QuadPart > 0)
				{
					dwRead = 0;

					if (!ReadFile(hFile, (PVOID)pTmp, liTmp.LowPart ? liTmp.LowPart : MAXDWORD, &dwRead, NULL) || dwRead == 0)
						break;

					pTmp		   += dwRead;
					liTmp.QuadPart -= dwRead;
				}

				if (liTmp.QuadPart == 0 && dwRead)
				{
					if (pSize)
					{
						*pSize = liSize.QuadPart + 1;
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

static SIZE_T CountLines(PCSTR pData)
{
	PCSTR  pLine = pData;
	SIZE_T Lines = 0;

	while (pLine = StrStrA(pLine, "\r\n"))
	{
		pLine += lstrlenA("\r\n");
		++Lines;
	}

	return Lines;
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

// The filename must start with one of the strings from gpCoinSymbols.
static COIN CoinFromFileName(PCWSTR pFileName)
{
	DWORD i;

	for (i = 0; i < ARRAYSIZE(g_CoinSymbols); ++i)
	{
		if (StrCmpNIW(pFileName, g_CoinSymbols[i].pSymbol, lstrlenW(g_CoinSymbols[i].pSymbol)) == 0)
			return g_CoinSymbols[i].Coin;
	}

	return C_INVALID;
}

static ALGORITHM AlgorithmFromCoin(COIN Coin)
{
	switch (Coin)
	{
	case C_BTC:
	case C_LTC:
		return A_1;
	case C_ETH:
		return A_2;
	default:
		return A_INVALID;
	}
}

static PCWSTR SymbolFromCoin(COIN Coin)
{
	return g_CoinSymbols[Coin].pSymbol;
}

static PCWSTR SymbolFromAddress(PCADDRESS pAddress)
{
	return SymbolFromCoin(pAddress->Coin);
}

// Ќе используетс€.
static PCNETWORK_PREFIX NetworkPrefixFromCoin(COIN Coin)
{
	return &g_NetworkPrefixes[Coin];
}

// ¬алидацию и декодирование адреса можно вынести в отдельные ф-ии (на каждую монету).
// Coin можно достать из адреса.
static BOOL DecodeAddress(COIN Coin, PCSTR pAddress, PADDRESS pAddresses)
{
	SIZE_T Len;
	BYTE   bBuf[64]; // !
	BOOL   Ok = FALSE;

	if (Len = lstrlenA(pAddress))
	{
		pAddresses->Coin = Coin;

		if (Coin == C_BTC && pAddress[0] == '1' || Coin == C_LTC && pAddress[0] == 'L')
		{
			if (Base58Decode(pAddress, bBuf, ARRAYSIZE(bBuf)) == 1 + DECODED_HASH_SIZE + 4)
			{
				CopyMemory((PVOID)pAddresses->bHash, (PCVOID)&bBuf[1], sizeof(pAddresses->bHash));
				Ok = TRUE;
			}
		}
		else if (Coin == C_ETH && StrCmpNIA(pAddress, "0x", lstrlenA("0x")) == 0)
		{
			if (Len == 42)
			{
				Ok = HexToBinA(&pAddress[2], pAddresses->bHash, ARRAYSIZE(pAddresses->bHash));
			}
		}
	}

	return Ok;
}

// ѕередавать dwLines, чтобы каким-нибудь образом не прочитать больше, чем позвол€ет буфер.
// Returns TRUE if at least one line has been processed.
static SIZE_T CopyAddresses(COIN Coin, PCSTR pData, PADDRESS pAddresses)
{
	PCSTR  pCRLF = NULL;
	CHAR   Address[64]; // !
	SIZE_T Count = 0;

	do
	{
		if (!(pCRLF = StrStrA(pData, "\r\n")))
			break;

		StringCchCopyNA(Address, ARRAYSIZE(Address), pData, pCRLF - pData);
		StrTrimA(Address, " \t");

		if (DecodeAddress(Coin, Address, pAddresses))
		{
			++pAddresses;
			++Count;
		}

		pData = pCRLF + lstrlenA("\r\n");

	} while (*pData);

	return Count;
}

// There should be no empty spaces between addresses (reallocation is required).
// TODO: MMF.
static SIZE_T ParseAddresses(COIN Coin, PCSTR pData, SIZE_T Lines)
{
	SIZE_T			Size,
					NewLines,
					OldSize;
	PADDRESS		pAddresses = NULL,
					pTmp	   = NULL;
	PALGORITHM_DATA pAlgData   = NULL;

	Size = Lines * sizeof(ADDRESS);

	if (pAddresses = (PADDRESS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size))
	{
		if (NewLines = CopyAddresses(Coin, pData, pAddresses))
		{
			if (NewLines == Lines || NewLines < Lines && (pTmp = (PADDRESS)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (PVOID)pAddresses, NewLines * sizeof(ADDRESS))))
			{
				if (pTmp)
				{
					pAddresses = pTmp;
					pTmp	   = NULL;
				}

				pAlgData = &g_AlgorithmData[AlgorithmFromCoin(Coin)];
				OldSize  = pAlgData->AddressCount * sizeof(ADDRESS);
				Size	 = NewLines				  * sizeof(ADDRESS);

				if (pTmp = pAlgData->pAddresses ? (PADDRESS)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (PVOID)pAlgData->pAddresses, OldSize + Size) : pAddresses)
				{
					// If the memory has already been allocated.
					if (pTmp != pAddresses)
					{
						CopyMemory((PVOID)&pTmp[pAlgData->AddressCount], (PCVOID)pAddresses, Size);

						HeapFree(GetProcessHeap(), 0, (PVOID)pAddresses);
						pAddresses = NULL;
					}

					pAlgData->pAddresses	= pTmp;
					pAlgData->AddressCount += NewLines;
					pTmp					= NULL;

					return NewLines;
				}
			}
		}

		HeapFree(GetProcessHeap(), 0, (PVOID)pAddresses);
		pAddresses = NULL;
	}

	return 0;
}

// ‘айлы должны быть в Ansi с .txt и '\r\n' (об€зательно в конце).
// Skips blank lines.
// TODO: MMF.
static BOOL LoadAddresses(VOID)
{
	WCHAR			 Path[MAX_PATH];
	WIN32_FIND_DATAW FindData;
	HANDLE			 hFind		 = INVALID_HANDLE_VALUE;
	SIZE_T			 AllFiles	 = 0,
					 AllLines,
					 LoadedLines,
					 LoadedFiles = 0;
	COIN			 Coin;
	PSTR			 pData		 = NULL;
	BOOL			 Ok			 = FALSE;

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
					++AllFiles;

					if ((Coin = CoinFromFileName(FindData.cFileName)) != C_INVALID)
					{
						PathRemoveFileSpecW(Path);
						StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Path, FindData.cFileName);

						if (pData = ReadFileData(Path, NULL))
						{
							if ((AllLines = CountLines(pData)) && (LoadedLines = ParseAddresses(Coin, pData, AllLines)))
							{
								wprintf(L"File %s loaded: %zu/%zu addresses.\n", FindData.cFileName, LoadedLines, AllLines);
								++LoadedFiles;
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

			if (!AllFiles)
			{
				wprintf(L"There are no files in the " DATA_FOLDER L" folder.\n");
			}

			Ok = GetLastError() == ERROR_NO_MORE_FILES && LoadedFiles /*&& AllFiles == LoadedFiles*/;

			FindClose(hFind);
			hFind = INVALID_HANDLE_VALUE;
		}
		else
			wprintf(DATA_FOLDER L" folder doesn't exist.\n");
	}
	else
		wprintf(L"Can't get path to " DATA_FOLDER L" folder.\n");

	wprintf(L"%zu/%zu files loaded.\n\n", LoadedFiles, AllFiles);

	return Ok;
}

// ѕереименовать.
// ѕопробовать вариант с inline и сравнить производительность.
// pbHash должен быть как минимум 32 байта (sha256).
static VOID HashFromPublicKey(ALGORITHM Algorithm, PCBYTE pbPulicKey, DWORD dwSize, PBYTE pbHash)
{
	switch (Algorithm)
	{
	case A_1:
		// bHash = RIPEMD160(SHA256(bPubKey))
		// The first 20 bytes of the hash.

		CryptSHA256(pbPulicKey, dwSize, pbHash);
		CryptRIPEMD160(pbHash, HASH_256_SIZE, pbHash);

		break;

	case A_2:
		// bHash = KECCAK256(bPubKey)
		// The last 20 bytes of the hash. They need to be moved to the beginning.

		CryptKECCAK256(&pbPulicKey[1], dwSize - 1, pbHash);
		MoveMemory((PVOID)pbHash, (PCVOID)&pbHash[HASH_256_SIZE - DECODED_HASH_SIZE], DECODED_HASH_SIZE);

		break;
	}
}

static VOID SavePrivateKey(PCADDRESS pAddress, PCBYTE pbPrivateKey, DWORD dwSize)
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

	wprintf(L"%s private key found: %S\n", SymbolFromAddress(pAddress), Buf);
}

/*
Range of valid ECDSA private keys:
	- Nearly every 256-bit number is a valid ECDSA private key. Specifically, any 256-bit number from 0x1 to
		0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140 is a valid private key.
	- The range of valid private keys is governed by the secp256k1 ECDSA standard used by Bitcoin.
*/

// ѕопробовать один контекст на все потоки.
// ѕопробовать вариант с брутом только BTC и сравнить производительность.
static DWORD WINAPI WorkerProc(PVOID pvParam)
{
	PEC_CONTEXT   pCtx = NULL;
	BYTE		  bPrivKey[SECP256K1_PRIVATE_KEY_SIZE],
				  bPubKey[SECP256K1_PUBLIC_KEY_SIZE],
				  bPubKeyComp[SECP256K1_PUBLIC_KEY_COMP_SIZE],
				  bHash[HASH_256_SIZE],
				  bHashComp[HASH_256_SIZE];
	EC_PUBLIC_KEY PubKey;
	ALGORITHM	  Alg;
	DWORD		  i;
	PCADDRESS	  pAddress = NULL;

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

					for (Alg = A_1; Alg < A_COUNT; ++Alg)
					{
						switch (Alg)
						{
						case A_1:
							HashFromPublicKey(Alg, bPubKey,		sizeof(bPubKey),	 bHash);
							HashFromPublicKey(Alg, bPubKeyComp, sizeof(bPubKeyComp), bHashComp);

							for (i = 0; i < g_AlgorithmData[Alg].AddressCount; ++i)
							{
								pAddress = &g_AlgorithmData[Alg].pAddresses[i];

								if (memcmp((PCVOID)bHash,	  (PCVOID)pAddress, RTL_FIELD_SIZE(ADDRESS, bHash)) == 0 ||
									memcmp((PCVOID)bHashComp, (PCVOID)pAddress, RTL_FIELD_SIZE(ADDRESS, bHash)) == 0)
								{
									SavePrivateKey(pAddress, bPrivKey, sizeof(bPrivKey));
								}
							}

							/*
							for (i = 0, pAddress = g_AlgorithmData[Alg].pAddresses; i < g_AlgorithmData[Alg].AddressCount; ++i, ++pAddress)
							{
								if (memcmp((PCVOID)bHash,	  (PCVOID)pAddress, RTL_FIELD_SIZE(ADDRESS, bHash)) == 0 ||
									memcmp((PCVOID)bHashComp, (PCVOID)pAddress, RTL_FIELD_SIZE(ADDRESS, bHash)) == 0)
								{
									SavePrivateKey(pAddress, bPrivKey, sizeof(bPrivKey));
								}
							}
							*/
							break;

						case A_2:
							HashFromPublicKey(Alg, bPubKey, sizeof(bPubKey), bHash);

							for (i = 0; i < g_AlgorithmData[Alg].AddressCount; ++i)
							{
								pAddress = &g_AlgorithmData[Alg].pAddresses[i];

								// ѕопробовать сравнивать с отступом вместо предварительного перемещени€ в начало.
								if (memcmp((PCVOID)bHash, (PCVOID)pAddress, RTL_FIELD_SIZE(ADDRESS, bHash)) == 0)
								{
									SavePrivateKey(pAddress, bPrivKey, sizeof(bPrivKey));
								}
							}

							/*
							for (i = 0, pAddress = g_AlgorithmData[Alg].pAddresses; i < g_AlgorithmData[Alg].AddressCount; ++i, ++pAddress)
							{
								// ѕопробовать сравнивать с отступом вместо предварительного перемещени€ в начало.
								if (memcmp((PCVOID)bHash, (PCVOID)pAddress, RTL_FIELD_SIZE(ADDRESS, bHash)) == 0)
								{
									SavePrivateKey(pAddress, bPrivKey, sizeof(bPrivKey));
								}
							}
							*/
							break;
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
