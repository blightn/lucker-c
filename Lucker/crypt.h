#ifndef _CRYPT_H_
#define _CRYPT_H_

#include "defines.h" // Выше не должно быть включений с "Windows.h", чтобы не перекрывать WIN32_LEAN_AND_MEAN.

#include <bcrypt.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <sha3.h>
#include <secp256k1.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "secp256k1.lib")

#define NT_SUCCESS(Status)			   (((NTSTATUS)(Status)) >= 0) // ntdef.h

#define HASH_256_SIZE				   32

#define	SECP256K1_PUBLIC_KEY_SIZE	   65
#define SECP256K1_PUBLIC_KEY_COMP_SIZE 33
#define SECP256K1_PRIVATE_KEY_SIZE	   32

typedef enum {
	ECT_SECP256K1
} EC_TYPE;

typedef secp256k1_context*		PEC_CONTEXT;
typedef secp256k1_pubkey		EC_PUBLIC_KEY;
typedef secp256k1_pubkey*		PEC_PUBLIC_KEY;
typedef const secp256k1_pubkey* PCEC_PUBLIC_KEY;

BOOL CryptRandomInit(VOID);
VOID CryptRandomCleanup(VOID);
BOOL CryptRandom(PBYTE pbData, DWORD dwSize);

VOID CryptSHA256(PCBYTE pbData, DWORD dwSize, PBYTE pbHash);
VOID CryptRIPEMD160(PCBYTE pbData, DWORD dwSize, PBYTE pbHash);
VOID CryptKECCAK256(PCBYTE pbData, DWORD dwSize, PBYTE pbHash);

PEC_CONTEXT CryptECContextCreate(EC_TYPE Type);
VOID CryptECContextDestroy(PEC_CONTEXT pCtx);

BOOL CryptECPublicKeyFromSecret(PEC_CONTEXT pCtx, PCBYTE pbSecret, PEC_PUBLIC_KEY pPubKey);
BOOL CryptECPublicKeyToBytes(PEC_CONTEXT pCtx, PCEC_PUBLIC_KEY pPubKey, BOOL Compress, PBYTE pbPubKey, DWORD dwSize);

#endif // _CRYPT_H_
