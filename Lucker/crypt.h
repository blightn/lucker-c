#ifndef _CRYPT_H_
#define _CRYPT_H_

#include "defines.h" // Выше не должно быть включений с "Windows.h", чтобы не перекрывать WIN32_LEAN_AND_MEAN.

#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0) // ntdef.h

BOOL CryptRandomInit(VOID);
VOID CryptRandomCleanup(VOID);
BOOL CryptRandom(PBYTE pbData, DWORD dwSize);

#endif // _CRYPT_H_
