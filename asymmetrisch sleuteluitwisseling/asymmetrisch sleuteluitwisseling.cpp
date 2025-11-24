// partij B (pB) genereert RSA keypair
// partij A (pA) gebruikt publieke sleutel om AES-sleutel veilig te sturen


#include <iostream>
#include <cassert>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

class AsymmetricKeyExchange {
public:
	// partij b genereert rsa keypair

	EVP_PKEY* generate_rsa_keypair() {
		EVP_PKEY* rsaKey = EVP_RSA_gen(2048);
		return rsaKey;
	}

	// partij A encrypt AES sleutel met publieke RSA sleutel van partij B
	unsigned char* encrypt_aes_key(EVP_PKEY_CTX* publicKey, unsigned char* aes_key) {

		//EVP_PKEY_encrypt();
		//return encrypted;
	}

	// partij B decrypt met privé sleutel
	unsigned char* decrypt_aes_key(EVP_PKEY* privateKey, unsigned char* encrypted) {
		/*EVP_PKEY_decrypt();
		return aes_key;*/
	}
};

int main() {
	AsymmetricKeyExchange exchange;

	// genergeer RSA keypair voor pB
	std::cout << "Partij B: Genereert RSA keypair..." << std::endl;
	EVP_PKEY* pB_keypair = exchange.generate_rsa_keypair();

	//  Publieke sleutel voor pB verkrijgen
	EVP_PKEY_CTX* pB_public;

	std::cout << "Partij A: Genereert AES-sleutel..." << std::endl;
	unsigned char aes_key[32];
	RAND_bytes(aes_key, 32);

	std::cout << "Partij A: Encrypt AES-sleutel met publieke sleutel Partij B..." << std::endl;
	unsigned char* encrypted_key = exchange.encrypt_aes_key(pB_public, aes_key);


	std::cout << "Partij B: Decrypt AES-sleutel met privé sleutel..." << std::endl;
	unsigned char* received_key = exchange.decrypt_aes_key(pB_keypair, encrypted_key);


	if (memcmp(aes_key, received_key, 32) == 0) {
		// Nu kunnen beide partijen symmetrisch communiceren
		std::cout << "Beide robots hebben nu dezelfde AES sleutel" << std::endl;
	}
}