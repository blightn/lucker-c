#ifndef _CRYPT_H_
#define _CRYPT_H_

#include "defines.h" // Выше не должно быть включений с "Windows.h", чтобы не перекрывать WIN32_LEAN_AND_MEAN.

#include <bcrypt.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "libcrypto.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0) // ntdef.h

BOOL CryptRandomInit(VOID);
VOID CryptRandomCleanup(VOID);
BOOL CryptRandom(PBYTE pbData, DWORD dwSize);

VOID CryptSHA256(PCBYTE pbData, DWORD dwSize, PBYTE pbHash);
VOID CryptRIPEMD160(PCBYTE pbData, DWORD dwSize, PBYTE pbHash);
VOID CryptKECCAK256(PCBYTE pbData, DWORD dwSize, PBYTE pbHash);

#endif // _CRYPT_H_
