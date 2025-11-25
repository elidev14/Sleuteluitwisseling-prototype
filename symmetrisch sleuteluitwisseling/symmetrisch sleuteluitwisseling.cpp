#include <iostream>
#include <chrono>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include "DiffieHellman.h"


typedef std::chrono::microseconds microseconds;

class TimeMeasure {
private:
	microseconds total{ 0 };
	std::chrono::high_resolution_clock::time_point start;

public:
	TimeMeasure() {
		resetEvent();
	}

	void resetEvent() {
		start = std::chrono::high_resolution_clock::now();
	}

	microseconds endEvent() {
		auto end = std::chrono::high_resolution_clock::now();
		microseconds duration = std::chrono::duration_cast<microseconds>(end - start);
		total += duration;
		return duration;
	}

	microseconds getTotal() const {
		return total;
	}
};


// Geen AES sleutel wordt ooit verstuurd
// twee partijen zelf een gedeelde sleutel.
// alleen geschikt als beide partijen gelijktijdig communiceren en private keys geheim blijven.
// Een plus is dat het een snelle execurtie heeft

int main() {

	TimeMeasure tm;

	DiffieHellman DH_pA, DH_pB;

	// Keypair generatie
	tm.resetEvent();
	DH_pA.generate_keypair();
	DH_pB.generate_keypair();
	microseconds genTime = tm.endEvent();

	std::cout << "keypairs gegenereerd in: "
		<< genTime.count() << " microseconden\n";

	// Public key exchange
	BIGNUM* pubA = DH_pA.get_public_key();
	BIGNUM* pubB = DH_pB.get_public_key();

	// Shared secret berekenen
	size_t secretA_len, secretB_len;

	tm.resetEvent();
	unsigned char* secretA = DH_pA.compute_shared_secret(pubB, secretA_len);
	microseconds compATime = tm.endEvent();

	tm.resetEvent();
	unsigned char* secretB = DH_pB.compute_shared_secret(pubA, secretB_len);
	microseconds compBTime = tm.endEvent();

	std::cout << "Shared secret berekend in:\n";
	std::cout << "  Alice: " << compATime.count() << " microseconden\n";
	std::cout << "  Bob:   " << compBTime.count() << " microseconden\n";

	// Verify
	if (secretA_len == secretB_len && memcmp(secretA, secretB, secretA_len) == 0)
		std::cout << "\nAlice en Bob hebben dezelfde gedeelde sleutel\n";
	else
		std::cout << "\nSleutels komen niet overeen\n";

	std::cout << "\nTotale tijd : "
		<< tm.getTotal().count() << " microseconden\n";

	OPENSSL_free(secretA);
	OPENSSL_free(secretB);

	return 0;
}
