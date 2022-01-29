#ifndef _WORKERS_H_
#define _WORKERS_H_

#include "defines.h" // Выше не должно быть включений с "Windows.h", чтобы не перекрывать WIN32_LEAN_AND_MEAN.

#include "base58.h"
#include "crypt.h"

#define DATA_FOLDER				L"Data"
#define NETWORK_PREFIX_SIZE_MIN 1
#define NETWORK_PREFIX_SIZE_MAX	2
#define DECODED_HASH_SIZE		20
#define ADDRESS_SIZE			(NETWORK_PREFIX_SIZE_MAX + DECODED_HASH_SIZE) // Не используется.

typedef enum {
	A_1,	 // sha256 + ripemd160
	A_2,	 // keccak256
	A_COUNT, // Number of algorithms.
	A_INVALID,
} ALGORITHM;

typedef enum {
	C_BTC,
	C_ETH,
	C_LTC,
	//C_COUNT,
	C_INVALID,
} COIN;

typedef struct
{
	COIN Coin;
	BYTE bHash[DECODED_HASH_SIZE]; // Создать тип.
} ADDRESS, *PADDRESS;

typedef const ADDRESS* PCADDRESS;

typedef struct
{
	PADDRESS pAddresses;
	SIZE_T	 AddressCount;
} ALGORITHM_DATA, *PALGORITHM_DATA;

typedef struct
{
	COIN   Coin;
	PCWSTR pSymbol;
} COIN_SYMBOL;

// Не используется.
typedef struct
{
	BYTE  bPrefix[NETWORK_PREFIX_SIZE_MAX];
	DWORD dwPrefixSize;
} NETWORK_PREFIX;

typedef const NETWORK_PREFIX* PCNETWORK_PREFIX;

BOOL StartWorkers(DWORD dwCount);
VOID StopWorkers(VOID);

DWORD64 GetCycleCount(VOID);

static BOOL GetDataPath(PWSTR pPath, DWORD dwSize);
static PSTR ReadFileData(PCWSTR pPath, PSIZE_T pSize);
static SIZE_T CountLines(PCSTR pData);

static BOOL HexToBin(BYTE bHex, PBYTE pbOut);
static BOOL HexToBinA(PCSTR pHex, PBYTE pbBuf, DWORD dwSize);

static COIN CoinFromFileName(PCWSTR pFileName);

static ALGORITHM AlgorithmFromCoin(COIN Coin);

static PCWSTR SymbolFromCoin(COIN Coin);
static PCWSTR SymbolFromAddress(PCADDRESS pAddress);

static PCNETWORK_PREFIX NetworkPrefixFromCoin(COIN Coin); // Не используется.

static BOOL DecodeAddress(COIN Coin, PCSTR pAddress, PADDRESS pAddresses);
static SIZE_T CopyAddresses(COIN Coin, PCSTR pData, PADDRESS pAddresses);
static SIZE_T ParseAddresses(COIN Coin, PCSTR pData, SIZE_T Lines);
static BOOL LoadAddresses(VOID);

static VOID HashFromPublicKey(ALGORITHM Algorithm, PCBYTE pbPulicKey, DWORD dwSize, PBYTE pbHash);
static VOID SavePrivateKey(PCADDRESS pAddress, PCBYTE pbPrivateKey, DWORD dwSize);
static DWORD WINAPI WorkerProc(PVOID pvParam);

#endif // _WORKERS_H_
