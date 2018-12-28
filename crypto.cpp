#include "crypto.hpp"

#define exp(k1,k2,i,s) _mm_xor_si128(expand(k1),\
_mm_shuffle_epi32(_mm_aeskeygenassist_si128(k2,i),s))
#define exp128(k,i) exp(k,k,i,0xff)
#define c(b) b-(b<58?48:55)

__m128i k[20];

static __m128i expand(__m128i key) {
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, _mm_slli_si128(key, 4));
}

Crypto::Aes128::Aes128(void *key) {
	k[0] = _mm_loadu_si128((__m128i *)key);
	k[1] = exp128(k[0], 0x01); k[2] = exp128(k[1], 0x02);
	k[3] = exp128(k[2], 0x04); k[4] = exp128(k[3], 0x08);
	k[5] = exp128(k[4], 0x10); k[6] = exp128(k[5], 0x20);
	k[7] = exp128(k[6], 0x40); k[8] = exp128(k[7], 0x80);
	k[9] = exp128(k[8], 0x1b); k[10] = exp128(k[9], 0x36);
	for (int i = 11; i <= 19; i++)
		k[i] = _mm_aesimc_si128(k[20 - i]);
}

void Crypto::Aes128::ECBEncryptBlock(void *pt, void *ct) {
	auto m = _mm_xor_si128(_mm_loadu_si128((__m128i *)pt), k[0]);
	m = _mm_aesenc_si128(m, k[1]);
	m = _mm_aesenc_si128(m, k[2]);
	m = _mm_aesenc_si128(m, k[3]);
	m = _mm_aesenc_si128(m, k[4]);
	m = _mm_aesenc_si128(m, k[5]);
	m = _mm_aesenc_si128(m, k[6]);
	m = _mm_aesenc_si128(m, k[7]);
	m = _mm_aesenc_si128(m, k[8]);
	m = _mm_aesenc_si128(m, k[9]);
	m = _mm_aesenclast_si128(m, k[10]);
	_mm_storeu_si128((__m128i *)ct, m);
}

void Crypto::Aes128::ECBDecryptBlock(void *ct, void *pt) {
	auto m = _mm_xor_si128(_mm_loadu_si128((__m128i *)ct), k[10]);
	m = _mm_aesdec_si128(m, k[11]);
	m = _mm_aesdec_si128(m, k[12]);
	m = _mm_aesdec_si128(m, k[13]);
	m = _mm_aesdec_si128(m, k[14]);
	m = _mm_aesdec_si128(m, k[15]);
	m = _mm_aesdec_si128(m, k[16]);
	m = _mm_aesdec_si128(m, k[17]);
	m = _mm_aesdec_si128(m, k[18]);
	m = _mm_aesdec_si128(m, k[19]);
	m = _mm_aesdeclast_si128(m, k[0]);
	_mm_storeu_si128((__m128i *)pt, m);
}

void Crypto::Aes128::CTRCryptBlock(void *pt, void *ct, void *ctr) {
	auto m = _mm_xor_si128(_mm_loadu_si128((__m128i *)ctr), k[0]);
	m = _mm_aesenc_si128(m, k[1]);
	m = _mm_aesenc_si128(m, k[2]);
	m = _mm_aesenc_si128(m, k[3]);
	m = _mm_aesenc_si128(m, k[4]);
	m = _mm_aesenc_si128(m, k[5]);
	m = _mm_aesenc_si128(m, k[6]);
	m = _mm_aesenc_si128(m, k[7]);
	m = _mm_aesenc_si128(m, k[8]);
	m = _mm_aesenc_si128(m, k[9]);
	m = _mm_aesenclast_si128(m, k[10]);
	_mm_storeu_si128((__m128i *)pt, 
		_mm_xor_si128(_mm_loadu_si128((__m128i *)ct), m));
}

void Crypto::Aes128::CTRIncrement(uint8_t *ctr) {
	for (int i = 15; i >= 0; i--)
		if (++ctr[i]) break;
}

void *Crypto::Util::ToHex(char*& x) {
	auto len = std::char_traits<char>::length(x) >> 1;
	auto *buf = new uint8_t[len];
	for (size_t i = 0; i < len; ++i)
		buf[i] = ((c(x[i << 1])) << 4) + (c(x[(i << 1) + 1]));
	return buf;
}