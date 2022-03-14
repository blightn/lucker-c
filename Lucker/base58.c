#include "base58.h"

static const CHAR g_Base58Digits[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const CHAR g_Base58Map[256] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
	-1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
	-1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
	47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

// Requires more space for pbBuf than necessary due temporary calculations.
BOOL Base58Encode(PCBYTE pbData, SIZE_T DataSize, PSTR pBuf, PSIZE_T pBufSize)
{
	SIZE_T ZeroCount,
	       Size,
	       i,
	       End,
	       j,
	       Carry;

	if (!DataSize)
	{
		*pBufSize = 0;
		return FALSE;
	}

	for (ZeroCount = 0; ZeroCount < DataSize && !pbData[ZeroCount]; ++ZeroCount);

	Size = (DataSize - ZeroCount) * 138 / 100 + 1;

	if (*pBufSize <= ZeroCount + Size)
	{
		*pBufSize = ZeroCount + Size + 1;
		return FALSE;
	}

	ZeroMemory((PVOID)pBuf, *pBufSize);

	for (i = ZeroCount, End = Size - 1; i < DataSize; ++i, End = j)
	{
		for (Carry = pbData[i], j = Size - 1; Carry || j > End; --j)
		{
			Carry  += (SIZE_T)pBuf[j] << 8;
			pBuf[j] = Carry % 58;
			Carry  /= 58;

			if (!j)
				break;
		}
	}

	for (j = 0; j < Size && !pBuf[j]; ++j);

	for (i = 0; j < Size; ++i, ++j)
	{
		pBuf[i] = g_Base58Digits[pBuf[j]];
	}

	if (ZeroCount)
	{
		MoveMemory((PVOID)&pBuf[ZeroCount], (PCVOID)pBuf, i);
		FillMemory((PVOID)pBuf, ZeroCount, '1');
	}

	i        += ZeroCount;
	pBuf[i]   = '\0';
	*pBufSize = i + 1;

	return TRUE;
}

// Requires more space for pbBuf than necessary due temporary calculations.
BOOL Base58Decode(PCSTR pData, PBYTE pbBuf, PSIZE_T pBufSize)
{
	SIZE_T Len,
	       Res,
	       i,
	       Carry,
	       j;
	BYTE   bTmp;

	Len      = lstrlenA(pData);
	Res      = 0;
	pbBuf[0] = 0x00;

	if (*pBufSize <= Len * 733 / 1000)
	{
		*pBufSize = Len * 733 / 1000 + 1;
		return FALSE;
	}

	for (i = 0; i < Len; ++i)
	{
		Carry = g_Base58Map[pData[i]];

		if (Carry == -1)
			return FALSE;

		for (j = 0; j < Res; ++j)
		{
			Carry   += pbBuf[j] * (SIZE_T)58;
			pbBuf[j] = Carry    & 0xFF;
			Carry  >>= 8;
		}

		while (Carry > 0)
		{
			pbBuf[Res++] = Carry & 0xFF;
			Carry      >>= 8;
		}
	}

	for (i = 0; i < Len && pData[i] == '1'; ++i)
	{
		pbBuf[Res++] = 0x00;
	}

	for (i = 0; i < Res / 2; ++i)
	{
		bTmp               = pbBuf[i];
		pbBuf[i]           = pbBuf[Res - i - 1];
		pbBuf[Res - i - 1] = bTmp;
	}

	*pBufSize = Res;

	return TRUE;
}
