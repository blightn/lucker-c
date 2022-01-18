#ifndef _BASE58_H_
#define _BASE58_H_

#include "defines.h" // Выше не должно быть включений с "Windows.h", чтобы не перекрывать WIN32_LEAN_AND_MEAN.

DWORD Base58Decode(PCSTR pData, PBYTE pbBuf, DWORD dwSize);

#endif // _BASE58_H_
