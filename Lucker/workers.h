#ifndef _WORKERS_H_
#define _WORKERS_H_

#include "defines.h"

#include "base58.h"
#include "crypt.h"

#define DATA_FOLDER				L"Data"
#define NETWORK_PREFIX_SIZE_MIN	1
#define NETWORK_PREFIX_SIZE_MAX	2
#define DECODED_HASH_SIZE		20
#define CHECKSUM_SIZE			4
#define LOOP_ITERATIONS         0xFF

typedef enum {
	A_1,	 // sha256 + ripemd160 (BTC, LTC, etc.)
	A_2,	 // keccak256 (ETH)
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

typedef enum {
	CT_BOTH,
	CT_UNCOMPRESSED,
	CT_COMPRESSED,
} COORDINATE_TYPE;

typedef struct {
	COIN Coin;
	BYTE bHash[DECODED_HASH_SIZE];
} ADDRESS, *PADDRESS;

typedef const ADDRESS* PCADDRESS;

typedef struct {
	PADDRESS pAddresses;
	SIZE_T	 AddressCount;
} ALGORITHM_DATA, *PALGORITHM_DATA;

typedef struct {
	COIN   Coin;
	PCWSTR pSymbol;
} COIN_SYMBOL;

typedef struct {
	BYTE  bPubPrefix[NETWORK_PREFIX_SIZE_MAX];
	DWORD dwPubPrefixSize;
	BYTE  bPrivPrefix[NETWORK_PREFIX_SIZE_MAX];
	DWORD dwPrivPrefixSize;
} NETWORK_PREFIXES;

typedef const NETWORK_PREFIXES* PCNETWORK_PREFIXES;

BOOL StartWorkers(DWORD dwCount, COORDINATE_TYPE CoordType, BOOL BindToCores, BOOL SMT);
VOID StopWorkers(VOID);

DWORD64 GetCycleCount(VOID);

static BOOL GetDataPath(PWSTR pPath, DWORD dwSize);
static PSTR ReadFileData(PCWSTR pPath, PSIZE_T pSize);
static BOOL WriteFileData(PCWSTR pPath, PCBYTE pbData, SIZE_T Size);
static SIZE_T CountLines(PCSTR pData);

static BOOL HexToBin(BYTE bHex, PBYTE pbOut);
static BOOL HexToBinA(PCSTR pHex, PBYTE pbBuf, DWORD dwSize);

static VOID BinToHex(PCBYTE pbData, DWORD dwDataSize, PSTR pBuf, DWORD dwBufSize);

static COIN CoinFromFileName(PCWSTR pFileName);

static ALGORITHM AlgorithmFromCoin(COIN Coin);

static PCWSTR SymbolFromCoin(COIN Coin);
static PCWSTR SymbolFromAddress(PCADDRESS pAddress);

static PCNETWORK_PREFIXES NetworkPrefixesFromCoin(COIN Coin);

static BOOL DecodeAddress(COIN Coin, PCSTR pAddress, PADDRESS pAddresses);
static SIZE_T CopyAddresses(COIN Coin, PCSTR pData, PADDRESS pAddresses);
static SIZE_T ParseAddresses(COIN Coin, PCSTR pData, SIZE_T Lines);
static BOOL LoadAddresses(VOID);

static VOID HashFromPublicKey(ALGORITHM Algorithm, PCBYTE pbPulicKey, DWORD dwSize, PBYTE pbHash);
static VOID PrivateKeyToWIF(PCBYTE pbPrivateKey, DWORD dwKeySize, COIN Coin, BOOL Compress, PSTR pBuf, DWORD dwBufSize);
static VOID AddressToString(PCADDRESS pAddress, PSTR pBuf, DWORD dwSize);
static VOID SavePrivateKey(PCADDRESS pAddress, PCBYTE pbPrivateKey, DWORD dwSize);

static DWORD WINAPI WorkerProc(PVOID pvParam);

#endif // _WORKERS_H_
