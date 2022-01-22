#ifndef _WORKERS_H_
#define _WORKERS_H_

#include "defines.h" // Выше не должно быть включений с "Windows.h", чтобы не перекрывать WIN32_LEAN_AND_MEAN.

#include "base58.h"
#include "crypt.h"

#define DATA_FOLDER			L"Data"
#define NETWORK_PREFIX_SIZE 2
#define DECODED_HASH_SIZE	20
#define ADDRESS_SIZE		(NETWORK_PREFIX_SIZE + DECODED_HASH_SIZE)

typedef enum {
	A_1,	 // sha256 + ripemd160
	A_2,	 // keccak256
	A_COUNT, // Number of algorithms.
	A_INVALID,
} ALGORITHM;

typedef enum {
	C_INVALID,
	C_BTC,
	C_ETH,
	C_LTC,
} COIN;

//typedef BYTE ADDRESS[DECODED_ADDRESS_SIZE], *PADDRESS[DECODED_ADDRESS_SIZE];

typedef struct
{
	SIZE_T AddressCount;
	PBYTE  pbAddresses; // 2 + 20 = 22 bytes each.
} ALGORITHM_DATA, *PALGORITHM_DATA;

typedef struct
{
	COIN  Coin;
	DWORD dwAddressCount;
	PBYTE pbAddresses; // 20 bytes each.
} COIN_DATA, *PCOIN_DATA;

BOOL StartWorkers(DWORD dwCount);
VOID StopWorkers(VOID);

DWORD64 GetCycleCount(VOID);

static BOOL GetDataPath(PWSTR pPath, DWORD dwSize);
static COIN CoinFromFileName(PCWSTR pFileName);
static PSTR ReadFileData(PCWSTR pPath, PDWORD pdwSize);
static DWORD CountLines(PCSTR pData);

static BOOL HexToBin(BYTE bHex, PBYTE pbOut);
static BOOL HexToBinA(PCSTR pHex, PBYTE pbBuf, DWORD dwSize);

static ALGORITHM AlgorithmFromCoin(COIN Coin);

static DWORD DecodeAddress(COIN Coin, PCSTR pAddress, PBYTE pbDecoded, DWORD dwSize);
static DWORD CopyAddresses(COIN Coin, PCSTR pData, PBYTE pbAddresses);
static SIZE_T ParseAddresses(COIN Coin, PCSTR pData, SIZE_T Lines);
static BOOL LoadAddresses(VOID);

static VOID HashFromPublicKey(COIN Coin, PCBYTE pbPulicKey, DWORD dwSize, PBYTE pbHash);
static VOID SavePrivateKey(COIN Coin, PCBYTE pbPrivateKey, DWORD dwSize);
static DWORD WINAPI WorkerProc(PVOID pvParam);

#endif // _WORKERS_H_
