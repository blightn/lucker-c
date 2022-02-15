#ifndef _BASE58_H_
#define _BASE58_H_

#include "defines.h"

BOOL Base58Encode(PCBYTE pbData, SIZE_T DataSize, PSTR pBuf, PSIZE_T pBufSize);
BOOL Base58Decode(PCSTR pData, PBYTE pbBuf, PSIZE_T pBufSize);

#endif // _BASE58_H_
