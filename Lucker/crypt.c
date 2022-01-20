#include "crypt.h"

static BCRYPT_ALG_HANDLE g_hRNGAlg = NULL; // Thread-safe?

// BCRYPT_RNG_FIPS186_DSA_ALGORITHM.
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

// Сравнить производительность с bcrypt.
// Сравнить производительность с EVP_Digest().
VOID CryptSHA256(PCBYTE pbData, DWORD dwSize, PBYTE pbHash)
{
	SHA256(pbData, dwSize, pbHash);
}

// Сравнить производительность с bcrypt.
// Сравнить производительность с EVP_Digest().
VOID CryptRIPEMD160(PCBYTE pbData, DWORD dwSize, PBYTE pbHash)
{
	RIPEMD160(pbData, dwSize, pbHash);
}

// Сравнить производительность с bcrypt.
// Сравнить производительность с EVP_Digest().
VOID CryptKECCAK256(PCBYTE pbData, DWORD dwSize, PBYTE pbHash)
{
	
}
