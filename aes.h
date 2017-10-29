#pragma once

#define AES_KEY_BYTES   (16) // 128 Bits
#define AES_BLOCK_BYTES (16)
#define AES_BLOCK_WORDS (AES_BLOCK_BYTES / sizeof(DWORD))
#define AES_KEY_DWORDS  (AES_KEY_BYTES / sizeof(DWORD))
#define V4_KEY_BYTES	(20) // 160 Bits

#define ROR32(v, n)  ( (v) << (32 - n) | (v) >> n )


typedef struct {
	DWORD  Key[48]; // Supports a maximum of 160 key bits!
	uint_fast8_t rounds;
} AesCtx;

void XorBlock(const BYTE *const pin, const BYTE *pout);
void AesInitKey(AesCtx *Ctx, const BYTE *Key, int_fast8_t IsV6, int AesKeyBytes);
void AesEncryptBlock(const AesCtx *const Ctx, BYTE *block);
void AesDecryptBlock(const AesCtx *const Ctx, BYTE *block);
void AesEncryptCbc(const AesCtx *const Ctx, BYTE * iv, BYTE * data, size_t * len);
void AesDecryptCbc(const AesCtx *const Ctx, BYTE *iv, BYTE *data, size_t len);
void AesCmacV4(BYTE *data, size_t len, BYTE *hash);

extern const BYTE AesKeyV4[];
extern const BYTE AesKeyV5[];
extern const BYTE AesKeyV6[];
