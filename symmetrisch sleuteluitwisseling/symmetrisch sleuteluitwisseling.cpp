#include <iostream>
#include <chrono>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include "DiffieHellman.h"
#include "ECDHKeyExchange.h"


// #define USE_ECDH         // ECDH testen
// #define USE_CLASSIC_DH // klassieke Diffie-Hellman testen

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


int main() {

	TimeMeasure tm;

#ifdef USE_CLASSIC_DH
	std::cout << "=== Classic Diffie Hellman ===\n";

	DiffieHellman DH_A, DH_B;

	// Keypair generatie
	tm.resetEvent();
	DH_A.generate_keypair();
	DH_B.generate_keypair();
	microseconds genTime = tm.endEvent();

	std::cout << "Keypairs gegenereerd in: "
		<< genTime.count() << " microseconden\n";

	// Public key exchange
	BIGNUM* pubA = DH_A.get_public_key();
	BIGNUM* pubB = DH_B.get_public_key();

	size_t secretA_len, secretB_len;

	tm.resetEvent();
	unsigned char* secretA = DH_A.compute_shared_secret(pubB, secretA_len);
	microseconds compATime = tm.endEvent();

	tm.resetEvent();
	unsigned char* secretB = DH_B.compute_shared_secret(pubA, secretB_len);
	microseconds compBTime = tm.endEvent();

	std::cout << "Shared secret berekend in:\n";
	std::cout << "  Alice: " << compATime.count() << " microseconden\n";
	std::cout << "  Bob:   " << compBTime.count() << " microseconden\n";

	if (secretA_len == secretB_len && memcmp(secretA, secretB, secretA_len) == 0)
		std::cout << "\nAlice en Bob hebben dezelfde gedeelde sleutel\n";
	else
		std::cout << "\nSleutels komen niet overeen\n";

	std::cout << "\nTotale tijd : "
		<< tm.getTotal().count() << " microseconden\n";

	OPENSSL_free(secretA);
	OPENSSL_free(secretB);

#endif



#ifdef USE_ECDH
	std::cout << "=== ECDH with us of the X25519 curve ===\n";

	ECDHKeyExchange A, B;

	// Keypair generatie
	tm.resetEvent();
	A.generate_keypair();
	B.generate_keypair();
	microseconds genTime = tm.endEvent();

	std::cout << "Keypairs gegenereerd in: "
		<< genTime.count() << " microseconden\n";

	// Public keys
	size_t a_pub_len = 0, b_pub_len = 0;

	unsigned char* a_pub = A.get_public_key(a_pub_len);
	unsigned char* b_pub = B.get_public_key(b_pub_len);

	// Shared secret
	size_t secA_len = 0, secB_len = 0;

	tm.resetEvent();
	unsigned char* secA = A.compute_shared_secret(b_pub, b_pub_len, secA_len);
	microseconds compATime = tm.endEvent();

	tm.resetEvent();
	unsigned char* secB = B.compute_shared_secret(a_pub, a_pub_len, secB_len);
	microseconds compBTime = tm.endEvent();

	std::cout << "Shared secret berekend in:\n";
	std::cout << "  Alice: " << compATime.count() << " microseconden\n";
	std::cout << "  Bob:   " << compBTime.count() << " microseconden\n";

	// Verify
	if (secA_len == secB_len && memcmp(secA, secB, secA_len) == 0)
		std::cout << "\nAlice en Bob hebben dezelfde gedeelde sleutel\n";
	else
		std::cout << "\nSleutels komen niet overeen\n";

	std::cout << "\nTotale tijd : "
		<< tm.getTotal().count() << " microseconden\n";

	OPENSSL_free(a_pub);
	OPENSSL_free(b_pub);
	OPENSSL_free(secA);
	OPENSSL_free(secB);

#endif

	return 0;
}
