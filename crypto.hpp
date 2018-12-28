#include <iostream>
#include <wmmintrin.h>

namespace Crypto {
	class Aes128 {
	public:
		Aes128(void *key);
		void ECBEncryptBlock(void *pt, void *ct);
		void ECBDecryptBlock(void *ct, void *pt);
		void CTRCryptBlock(void *pt, void *ct, void *ctr);
		static void CTRIncrement(uint8_t *ctr);
	};

	struct Util {
		static void *ToHex(char*&);
	};
}