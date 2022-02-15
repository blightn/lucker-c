#include "crypt.h"

static BCRYPT_ALG_HANDLE g_hRNGAlg = NULL;

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

VOID CryptSHA256(PCBYTE pbData, DWORD dwSize, PBYTE pbHash)
{
	SHA256(pbData, dwSize, pbHash);
}

VOID CryptRIPEMD160(PCBYTE pbData, DWORD dwSize, PBYTE pbHash)
{
	RIPEMD160(pbData, dwSize, pbHash);
}

VOID CryptKECCAK256(PCBYTE pbData, DWORD dwSize, PBYTE pbHash)
{
	sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, (PCVOID)pbData, dwSize, (PVOID)pbHash, HASH_256_SIZE);
}

PEC_CONTEXT CryptECContextCreate(EC_TYPE Type)
{
	return secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
}

VOID CryptECContextDestroy(PEC_CONTEXT pCtx)
{
	secp256k1_context_destroy(pCtx);
}

BOOL CryptECPublicKeyFromSecret(PEC_CONTEXT pCtx, PCBYTE pbSecret, PEC_PUBLIC_KEY pPubKey)
{
	return secp256k1_ec_pubkey_create(pCtx, pPubKey, pbSecret);
}

BOOL CryptECPublicKeyToBytes(PEC_CONTEXT pCtx, PCEC_PUBLIC_KEY pPubKey, BOOL Compress, PBYTE pbPubKey, DWORD dwSize)
{
	SIZE_T Size = dwSize;

	return secp256k1_ec_pubkey_serialize(pCtx, pbPubKey, &Size, pPubKey, Compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
}
