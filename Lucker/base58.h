#ifndef _BASE58_H_
#define _BASE58_H_

#include "defines.h" // ���� �� ������ ���� ��������� � "Windows.h", ����� �� ����������� WIN32_LEAN_AND_MEAN.

DWORD Base58Decode(PCSTR pData, PBYTE pbBuf, DWORD dwSize);

#endif // _BASE58_H_
