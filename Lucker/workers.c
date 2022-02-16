#include "workers.h"

static const COIN_SYMBOL g_CoinSymbols[] =
{
	{ C_BTC, L"BTC" },
	{ C_ETH, L"ETH" },
	{ C_LTC, L"LTC" },
};

static const NETWORK_PREFIXES g_NetworkPrefixes[] =
{
	{ { 0x00, 0x00 }, 1, { 0x80, 0x00 }, 1 }, // BTC
	{ {  '0',  'x' }, 2, { 0x00, 0x00 }, 0 }, // ETH
	{ { 0x30, 0x00 }, 1, { 0xB0, 0x00 }, 1 }, // LTC
};

static DWORD          g_dwWorkers;
static ALGORITHM_DATA g_AlgorithmData[A_COUNT];
static HANDLE         g_hStopEvent = NULL;
static PHANDLE        g_phWorkers  = NULL;

static volatile DWORD64 g_qwCycles;

BOOL StartWorkers(DWORD dwCount, COORDINATE_TYPE CoordType, BOOL BindToCores, BOOL SMT)
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
							if (!(g_phWorkers[i] = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)WorkerProc, (PVOID)CoordType, 0, NULL)))
								break;

							if (BindToCores)
							{
								SetThreadAffinityMask(g_phWorkers[i], (DWORD_PTR)(1ULL << (i + i * SMT)));
							}
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

	if ((hFile = CreateFileW(pPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL)) != INVALID_HANDLE_VALUE)
	{
#ifdef _WIN64
		if (GetFileSizeEx(hFile, &liSize) && liSize.QuadPart && liSize.QuadPart < MAXDWORD64)
#else
		if (GetFileSizeEx(hFile, &liSize) && liSize.QuadPart && !liSize.HighPart && liSize.LowPart < MAXDWORD)
#endif
		{
			if (pData = (PSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)liSize.QuadPart + 1)) // +1 for '\0'.
			{
				pTmp  = pData;
				liTmp = liSize;

				while (liTmp.QuadPart > 0)
				{
					dwRead = 0;

					if (!ReadFile(hFile, (PVOID)pTmp, liTmp.LowPart ? liTmp.LowPart : MAXDWORD, &dwRead, NULL) || !dwRead)
						break;

					pTmp		   += dwRead;
					liTmp.QuadPart -= dwRead;
				}

				if (!liTmp.QuadPart && dwRead)
				{
					if (pSize)
					{
						*pSize = (SIZE_T)liSize.QuadPart + 1;
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

// TODO: MMF.
static BOOL WriteFileData(PCWSTR pPath, PCBYTE pbData, SIZE_T Size)
{
	HANDLE		  hFile		= INVALID_HANDLE_VALUE;
	LARGE_INTEGER liSize;
	DWORD		  dwWritten	= 0;
	BOOL		  Ok		= FALSE;

	if ((hFile = CreateFileW(pPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL)) != INVALID_HANDLE_VALUE)
	{
		SetFilePointer(hFile, 0L, NULL, FILE_END);
		liSize.QuadPart = Size;

		while (liSize.QuadPart > 0)
		{
			dwWritten = 0;

			if (!(WriteFile(hFile, (PCVOID)pbData, liSize.LowPart ? liSize.LowPart : MAXDWORD, &dwWritten, NULL)) || !dwWritten)
				break;

			pbData			+= dwWritten;
			liSize.QuadPart -= dwWritten;
		}

		Ok = liSize.QuadPart == 0 && dwWritten;

		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}

	return Ok;
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

static VOID BinToHex(PCBYTE pbData, DWORD dwDataSize, PSTR pBuf, DWORD dwBufSize)
{
	DWORD i;

	for (i = 0; i < dwDataSize; ++i)
	{
		StringCchPrintfA(pBuf, dwBufSize, "%s%02x", pBuf, pbData[i]);
	}
}

// The filename must start with one of the strings from g_CoinSymbols.
static COIN CoinFromFileName(PCWSTR pFileName)
{
	DWORD i;

	for (i = 0; i < ARRAYSIZE(g_CoinSymbols); ++i)
	{
		if (!StrCmpNIW(pFileName, g_CoinSymbols[i].pSymbol, lstrlenW(g_CoinSymbols[i].pSymbol)))
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

static PCNETWORK_PREFIXES NetworkPrefixesFromCoin(COIN Coin)
{
	return &g_NetworkPrefixes[Coin];
}

static BOOL DecodeAddress(COIN Coin, PCSTR pAddress, PADDRESS pAddresses)
{
	SIZE_T Len,
		   Size;
	BYTE   bBuf[64];
	BOOL   Ok = FALSE;

	if (Len = lstrlenA(pAddress))
	{
		pAddresses->Coin = Coin;

		if (Coin == C_BTC && pAddress[0] == '1' || Coin == C_LTC && pAddress[0] == 'L')
		{
			Size = ARRAYSIZE(bBuf);

			if (Base58Decode(pAddress, bBuf, &Size) && Size == 1 + DECODED_HASH_SIZE + 4)
			{
				CopyMemory((PVOID)pAddresses->bHash, (PCVOID)&bBuf[1], sizeof(pAddresses->bHash));
				Ok = TRUE;
			}
		}
		else if (Coin == C_ETH && !StrCmpNIA(pAddress, "0x", lstrlenA("0x")))
		{
			if (Len == 42)
			{
				Ok = HexToBinA(&pAddress[2], pAddresses->bHash, ARRAYSIZE(pAddresses->bHash));
			}
		}
	}

	return Ok;
}

// Returns TRUE if at least one line has been processed.
static SIZE_T CopyAddresses(COIN Coin, PCSTR pData, PADDRESS pAddresses)
{
	PCSTR  pCRLF = NULL;
	CHAR   Address[64];
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
		else
			wprintf(L"Invalid address: %S\n", Address);

		pData = pCRLF + lstrlenA("\r\n");

	} while (*pData);

	return Count;
}

// There should be no empty spaces between addresses (reallocation is required).
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
			if (NewLines == Lines || NewLines < Lines && (pTmp = (PADDRESS)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
				(PVOID)pAddresses, NewLines * sizeof(ADDRESS))))
			{
				if (pTmp)
				{
					pAddresses = pTmp;
					pTmp	   = NULL;
				}

				pAlgData = &g_AlgorithmData[AlgorithmFromCoin(Coin)];
				OldSize  = pAlgData->AddressCount * sizeof(ADDRESS);
				Size	 = NewLines				  * sizeof(ADDRESS);

				if (pTmp = pAlgData->pAddresses ? (PADDRESS)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
					(PVOID)pAlgData->pAddresses, OldSize + Size) : pAddresses)
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

// Encoding can be ANSI or UTF-8. Lines within files must be separated by "\r\n". At the end of the file must be an empty line.
static BOOL LoadAddresses(VOID)
{
	WCHAR			 Path[MAX_PATH];
	WIN32_FIND_DATAW FindData;
	HANDLE			 hFind		 = INVALID_HANDLE_VALUE;
	SIZE_T			 AllFiles	 = 0,
		             FileLines,
		             ParsedLines,
		             LoadedFiles = 0,
					 LoadedLines = 0;
	COIN			 Coin;
	PSTR			 pData		 = NULL;
	BOOL			 Ok			 = FALSE;

	wprintf(L"Loading files with addresses...\n");

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
						wprintf(L"Loading file %s...\n", FindData.cFileName);

						PathRemoveFileSpecW(Path);
						StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Path, FindData.cFileName);

						if (pData = ReadFileData(Path, NULL))
						{
							if ((FileLines = CountLines(pData)) && (ParsedLines = ParseAddresses(Coin, pData, FileLines)))
							{
								wprintf(L"File %s loaded: %zu/%zu addresses.\n", FindData.cFileName, ParsedLines, FileLines);

								++LoadedFiles;
								LoadedLines += ParsedLines;
							}
							else
								wprintf(L"Can't load file: %s\n", FindData.cFileName);

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

			Ok = GetLastError() == ERROR_NO_MORE_FILES && LoadedFiles;

			FindClose(hFind);
			hFind = INVALID_HANDLE_VALUE;
		}
		else
			wprintf(DATA_FOLDER L" folder doesn't exist.\n");
	}
	else
		wprintf(L"Can't get path to " DATA_FOLDER L" folder.\n");

	wprintf(L"%zu/%zu files loaded.\n", LoadedFiles, AllFiles);
	wprintf(L"%zu addresses loaded.\n\n", LoadedLines);

	return Ok;
}

// pbHash size must be at least 32 bytes (sha256).
static VOID HashFromPublicKey(ALGORITHM Algorithm, PCBYTE pbPulicKey, DWORD dwSize, PBYTE pbHash)
{
	switch (Algorithm)
	{
	case A_1:
		// The first 20 bytes of RIPEMD160(SHA256(bPubKey)).
		CryptSHA256(pbPulicKey, dwSize, pbHash);
		CryptRIPEMD160(pbHash, HASH_256_SIZE, pbHash);
		break;

	case A_2:
		// The last 20 bytes of KECCAK256(bPubKey). They need to be moved to the beginning.
		CryptKECCAK256(&pbPulicKey[1], dwSize - 1, pbHash);
		MoveMemory((PVOID)pbHash, (PCVOID)&pbHash[HASH_256_SIZE - DECODED_HASH_SIZE], DECODED_HASH_SIZE);
		break;
	}
}

static VOID PrivateKeyToWIF(PCBYTE pbPrivateKey, DWORD dwKeySize, COIN Coin, BOOL Compress, PSTR pBuf, DWORD dwBufSize)
{
	PCNETWORK_PREFIXES pPrefixes = NULL;
	BYTE			   bBuf[64],
					   bHash[HASH_256_SIZE];
	DWORD			   dwResSize = 0;
	SIZE_T             Size;

	if (Coin == C_ETH)
		return;

	pPrefixes = NetworkPrefixesFromCoin(Coin);

	CopyMemory((PVOID)bBuf,	(PCVOID)pPrefixes->bPrivPrefix, pPrefixes->dwPrivPrefixSize);
	dwResSize += pPrefixes->dwPrivPrefixSize;

	CopyMemory((PVOID)&bBuf[dwResSize], (PCVOID)pbPrivateKey, dwKeySize);
	dwResSize += dwKeySize;

	if (Compress)
	{
		bBuf[dwResSize] = 0x01;
		dwResSize      += 1;
	}

	CryptSHA256(bBuf,  dwResSize,	  bHash);
	CryptSHA256(bHash, HASH_256_SIZE, bHash);

	CopyMemory((PVOID)&bBuf[dwResSize], (PCVOID)bHash, CHECKSUM_SIZE);
	dwResSize += CHECKSUM_SIZE;

	Size = dwBufSize;

	if (!Base58Encode(bBuf, dwResSize, pBuf, &Size))
	{
		StringCchCopyA(pBuf, dwBufSize, "-");
	}
}

static VOID AddressToString(PCADDRESS pAddress, PSTR pBuf, DWORD dwSize)
{
	PCNETWORK_PREFIXES pPrefixes = NULL;
	BYTE			   bBuf[64],
					   bHash[HASH_256_SIZE];
	DWORD			   dwResSize = 0;
	SIZE_T             Size;

	pPrefixes = NetworkPrefixesFromCoin(pAddress->Coin);

	if (pAddress->Coin != C_ETH)
	{
		CopyMemory((PVOID)bBuf, (PCVOID)pPrefixes->bPubPrefix, pPrefixes->dwPubPrefixSize);
		dwResSize += pPrefixes->dwPubPrefixSize;

		CopyMemory((PVOID)&bBuf[dwResSize], (PCVOID)pAddress->bHash, sizeof(pAddress->bHash));
		dwResSize += sizeof(pAddress->bHash);

		CryptSHA256(bBuf,  dwResSize,	  bHash);
		CryptSHA256(bHash, HASH_256_SIZE, bHash);

		CopyMemory((PVOID)&bBuf[dwResSize], (PCVOID)bHash, CHECKSUM_SIZE);
		dwResSize += CHECKSUM_SIZE;

		Size = dwSize;

		if (!Base58Encode(bBuf, dwResSize, pBuf, &Size))
		{
			StringCchCopyA(pBuf, dwSize, "-");
		}
	}
	else
	{
		CopyMemory((PVOID)pBuf, (PCVOID)pPrefixes->bPubPrefix, pPrefixes->dwPubPrefixSize);
		dwResSize += pPrefixes->dwPubPrefixSize;

		pBuf[dwResSize] = '\0';
		BinToHex(pAddress->bHash, sizeof(pAddress->bHash), &pBuf[dwResSize], dwSize);
	}
}

/*
BTC private key found (HEX): 5500a1ff8378cc2c257bcd6d3d0186ac9fb9d226154f793f7bcb892efb34ebc7
Private key (WIF, uncompressed): 5JTiraPKabEVkVyLFJSCaKcn343iFBULYy25mL4QM6fVhFSJ2od
Private key (WIF, compressed): Kz4wjpMX1G6Ztzsdx7xE65Aun4Sy3bDfJ6Fn2f823hzueGZNQes6
Address: 12fokXPiUNSVvab6gxGo7Zgni2VYZS8A4x

ETH private key found (HEX): 5500a1ff8378cc2c257bcd6d3d0186ac9fb9d226154f793f7bcb892efb34ebc7
Address: 0x38e73420d07d32c789b4349988fd67a667a61892
*/
static VOID SavePrivateKey(PCADDRESS pAddress, PCBYTE pbPrivateKey, DWORD dwSize)
{
	CHAR  Buf[512],
		  Tmp[64];
	WCHAR Path[MAX_PATH];

	StringCchPrintfA(Buf, ARRAYSIZE(Buf), "\r\n%S private key found (HEX): ", SymbolFromAddress(pAddress));

	BinToHex(pbPrivateKey, dwSize, Buf, ARRAYSIZE(Buf));
	StringCchCatA(Buf, ARRAYSIZE(Buf), "\r\n");

	switch (pAddress->Coin)
	{
	case C_BTC:
	case C_LTC:
		PrivateKeyToWIF(pbPrivateKey, dwSize, pAddress->Coin, FALSE, Tmp, ARRAYSIZE(Tmp));
		StringCchPrintfA(Buf, ARRAYSIZE(Buf), "%sPrivate key (WIF, uncompressed): %s\r\n", Buf, Tmp);

		PrivateKeyToWIF(pbPrivateKey, dwSize, pAddress->Coin, TRUE, Tmp, ARRAYSIZE(Tmp));
		StringCchPrintfA(Buf, ARRAYSIZE(Buf), "%sPrivate key (WIF, compressed): %s\r\n", Buf, Tmp);

	case C_ETH:
		AddressToString(pAddress, Tmp, ARRAYSIZE(Tmp));
		StringCchPrintfA(Buf, ARRAYSIZE(Buf), "%sAddress: %s\r\n", Buf, Tmp);
		break;
	}

	printf(Buf);
	printf("\n");

	if (GetDataPath(Path, ARRAYSIZE(Path)))
	{
		StringCchCatW(Path, ARRAYSIZE(Path), L"Result.txt");
		WriteFileData(Path, (PCBYTE)Buf, lstrlenA(Buf));
	}
	else
		wprintf(L"Can't save private key to file.\n");
}

/*
Range of valid ECDSA private keys:
	- Nearly every 256-bit number is a valid ECDSA private key. Specifically, any 256-bit number from 0x1 to
		0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140 is a valid private key.
	- The range of valid private keys is governed by the secp256k1 ECDSA standard used by Bitcoin.
*/
static DWORD WINAPI WorkerProc(PVOID pvParam)
{
	COORDINATE_TYPE CoordType = (COORDINATE_TYPE)pvParam;
	PEC_CONTEXT		pCtx	  = NULL;
	DWORD			i,
					j;
	BYTE			bPrivKey[SECP256K1_PRIVATE_KEY_SIZE],
					bPubKey[SECP256K1_PUBLIC_KEY_SIZE],
					bPubKeyComp[SECP256K1_PUBLIC_KEY_COMP_SIZE],
					bHash[HASH_256_SIZE],
					bHashComp[HASH_256_SIZE];
	EC_PUBLIC_KEY	PubKey;
	ALGORITHM		Alg;
	PCADDRESS		pAddress  = NULL;

	if (pCtx = CryptECContextCreate(ECT_SECP256K1))
	{
		while (WaitForSingleObject(g_hStopEvent, 0) == WAIT_TIMEOUT)
		{
			for (i = 0; i < LOOP_ITERATIONS; ++i)
			{
				// We randomize all 32 bytes without checking the range, because the chance of getting a zero or
				// a value greater than 0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140
				// is very small, but much more than a chance to get the right address ;)
				if (CryptRandom(bPrivKey, sizeof(bPrivKey)))
				{
					if (CryptECPublicKeyFromSecret(pCtx, bPrivKey, &PubKey))
					{
						for (Alg = A_1; Alg < A_COUNT; ++Alg)
						{
							switch (Alg)
							{
							case A_1:
								if (CoordType == CT_BOTH)
								{
									CryptECPublicKeyToBytes(pCtx, &PubKey, FALSE, bPubKey,     sizeof(bPubKey)    );
									CryptECPublicKeyToBytes(pCtx, &PubKey, TRUE,  bPubKeyComp, sizeof(bPubKeyComp));

									HashFromPublicKey(Alg, bPubKey,     sizeof(bPubKey),     bHash    );
									HashFromPublicKey(Alg, bPubKeyComp, sizeof(bPubKeyComp), bHashComp);

									for (j = 0, pAddress = g_AlgorithmData[Alg].pAddresses; j < g_AlgorithmData[Alg].AddressCount; ++j, ++pAddress)
									{
										if (!memcmp((PCVOID)bHash,     (PCVOID)pAddress->bHash, sizeof(pAddress->bHash)) ||
											!memcmp((PCVOID)bHashComp, (PCVOID)pAddress->bHash, sizeof(pAddress->bHash)))
										{
											SavePrivateKey(pAddress, bPrivKey, sizeof(bPrivKey));
										}
									}
								}
								else if (CoordType == CT_UNCOMPRESSED)
								{
									CryptECPublicKeyToBytes(pCtx, &PubKey, FALSE, bPubKey, sizeof(bPubKey));
									HashFromPublicKey(Alg, bPubKey, sizeof(bPubKey), bHash);

									for (j = 0, pAddress = g_AlgorithmData[Alg].pAddresses; j < g_AlgorithmData[Alg].AddressCount; ++j, ++pAddress)
									{
										if (!memcmp((PCVOID)bHash, (PCVOID)pAddress->bHash, sizeof(pAddress->bHash)))
										{
											SavePrivateKey(pAddress, bPrivKey, sizeof(bPrivKey));
										}
									}
								}
								else // CoordType == CT_COMPRESSED
								{
									CryptECPublicKeyToBytes(pCtx, &PubKey, TRUE, bPubKeyComp, sizeof(bPubKeyComp));
									HashFromPublicKey(Alg, bPubKeyComp, sizeof(bPubKeyComp), bHashComp);

									for (j = 0, pAddress = g_AlgorithmData[Alg].pAddresses; j < g_AlgorithmData[Alg].AddressCount; ++j, ++pAddress)
									{
										if (!memcmp((PCVOID)bHashComp, (PCVOID)pAddress->bHash, sizeof(pAddress->bHash)))
										{
											SavePrivateKey(pAddress, bPrivKey, sizeof(bPrivKey));
										}
									}
								}
								break;

							case A_2:
								CryptECPublicKeyToBytes(pCtx, &PubKey, FALSE, bPubKey, sizeof(bPubKey));
								HashFromPublicKey(Alg, bPubKey, sizeof(bPubKey), bHash);

								for (j = 0, pAddress = g_AlgorithmData[Alg].pAddresses; j < g_AlgorithmData[Alg].AddressCount; ++j, ++pAddress)
								{
									if (!memcmp((PCVOID)bHash, (PCVOID)pAddress->bHash, sizeof(pAddress->bHash)))
									{
										SavePrivateKey(pAddress, bPrivKey, sizeof(bPrivKey));
									}
								}
								break;
							}
						}
					}
				}
			}

			InterlockedAdd64(&g_qwCycles, LOOP_ITERATIONS);
		}

		CryptECContextDestroy(pCtx);
		pCtx = NULL;
	}

	return 0;
}
