#ifndef _WORKERS_H_
#define _WORKERS_H_

#include "defines.h" // ���� �� ������ ���� ��������� � "Windows.h", ����� �� ����������� WIN32_LEAN_AND_MEAN.

#include <secp256k1.h>

#include "base58.h"
#include "crypt.h"

#pragma comment(lib, "secp256k1.lib")

#define DATA_FOLDER			 L"Data"
#define DECODED_ADDRESS_SIZE 20
#define	PUBLIC_KEY_SIZE		 65
#define PUBLIC_KEY_COMP_SIZE 33
#define PRIVATE_KEY_SIZE	 32
#define HASH_256_SIZE		 32

typedef enum {
	C_INVALID,
	C_BTC,
	C_ETH,
	C_LTC,
} COIN;

typedef struct
{
	COIN  Coin;
	DWORD dwAddressCount;
	PBYTE pbAddresses; // 20 bytes each.
} COIN_DATA, *PCOIN_DATA;

typedef secp256k1_context* PSECP256K1_CONTEXT;
typedef secp256k1_pubkey   SECP256K1_PUBKEY;

BOOL StartWorkers(DWORD dwCount);
VOID StopWorkers(VOID);

DWORD64 GetCycleCount(VOID);

static BOOL GetDataPath(PWSTR pPath, DWORD dwSize);
static COIN CoinFromFileName(PCWSTR pFileName);
static PSTR ReadFileData(PCWSTR pPath, PDWORD pdwSize);
static DWORD CountLines(PCSTR pData);

static BOOL HexToBin(BYTE bHex, PBYTE pbOut);
static BOOL HexToBinA(PCSTR pHex, PBYTE pbBuf, DWORD dwSize);

static DWORD DecodeAddress(COIN Coin, PCSTR pAddress, PBYTE pbDecoded, DWORD dwSize);
static DWORD CopyAddresses(COIN Coin, PCSTR pData, PBYTE pbAddresses);
static DWORD ParseAddresses(COIN Coin, PCSTR pData, DWORD dwLines);
static BOOL LoadAddresses(VOID);

static VOID HashFromPublicKey(COIN Coin, PCBYTE pbPulicKey, DWORD dwSize, PBYTE pbHash);
static VOID SavePrivateKey(COIN Coin, PCBYTE pbPrivateKey, DWORD dwSize);
static DWORD WINAPI WorkerProc(PVOID pvParam);

#endif // _WORKERS_H_
