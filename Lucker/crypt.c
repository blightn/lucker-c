#include "crypt.h"

static BCRYPT_ALG_HANDLE g_hRNGAlg = NULL; // Thread-safe?

// Попробовать BCRYPT_RNG_FIPS186_DSA_ALGORITHM вместо BCRYPT_RNG_ALGORITHM.
BOOL CryptRandomInit(VOID)
{
	return NT_SUCCESS(BCryptOpenAlgorithmProvider(&g_hRNGAlg, BCRYPT_RNG_ALGORITHM, NULL, 0));
}

VOID CryptRandomCleanup(VOID)
{
	if (g_hRNGAlg)
	{
		BCryptCloseAlgorithmProvider(g_hRNGAlg, 0);
		g_hRNGAlg = NULL;
	}
}

BOOL CryptRandom(PBYTE pbData, DWORD dwSize)
{
	return NT_SUCCESS(BCryptGenRandom(g_hRNGAlg, (PUCHAR)pbData, dwSize, 0));
}
