#include <iostream>
#include <chrono>

#include "crypto.hpp"

int __cdecl main(int argc, char **argv) {

	uint8_t pt[0x10]{0},
			ct[0x10]{0},
			kt[0x10]{0};
		
	auto crypt = new Crypto::Aes128(kt);

	auto begin = std::chrono::high_resolution_clock::now();

	for (long long i = 0; i < 0x190000000; i++)
		crypt->ECBEncryptBlock(pt, ct);

	auto end = std::chrono::high_resolution_clock::now();

	std::cout << 
		"Encrypted 100GiB in " << 
		std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count() << 
		"ms." << 
		std::endl;

	std::cout << "Final block: ";

	for (int i = 0; i < 0x10; i++)
		printf("%02x", ct[i]);
}