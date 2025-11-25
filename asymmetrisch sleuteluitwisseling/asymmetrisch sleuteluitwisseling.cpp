// Bob(kpB) genereert RSA keypair
// Alice(pA) gebruikt publieke sleutel om aes sleutel veilig te sturen


#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <cstring>
#include <iostream>
#include <chrono>

using namespace std::chrono_literals;

class AsymmetricKeyExchange {
public:

    // Bob genereert RSA keypair (2048 bits)
    EVP_PKEY* generate_rsa_keypair() {
        EVP_PKEY* rsaKey = EVP_RSA_gen(2048);
        return rsaKey;
    }

    // Alice encrypt aes sleutel met publieke RSA sleutel van bob
    unsigned char* encrypt_aes_key(EVP_PKEY* publicKey, unsigned char* aes_key, size_t& out_len) {

		//Zet de publieke sleutel om naar context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, nullptr);
        if (!ctx) return nullptr;


        if (EVP_PKEY_encrypt_init(ctx) <= 0) return nullptr;

        // RSA OAEP
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

        // Eerst output length bepalen
        EVP_PKEY_encrypt(ctx, nullptr, &out_len, aes_key, 32);

        unsigned char* encrypted = (unsigned char*)OPENSSL_malloc(out_len);

        // De encryptie
        if (EVP_PKEY_encrypt(ctx, encrypted, &out_len, aes_key, 32) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            OPENSSL_free(encrypted);
            return nullptr;
        }

        EVP_PKEY_CTX_free(ctx);
        return encrypted;
    }

    // Bob decrypt met prive sleutel
    unsigned char* decrypt_aes_key(EVP_PKEY* privateKey, unsigned char* encrypted, size_t encrypted_len) {

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
        if (!ctx) return nullptr;

        if (EVP_PKEY_decrypt_init(ctx) <= 0) return nullptr;

        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

        size_t out_len = 0;

        // lengte bepalen
        EVP_PKEY_decrypt(ctx, nullptr, &out_len, encrypted, encrypted_len);

        unsigned char* decrypted = (unsigned char*)OPENSSL_malloc(out_len);

        if (EVP_PKEY_decrypt(ctx, decrypted, &out_len, encrypted, encrypted_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            OPENSSL_free(decrypted);
            return nullptr;
        }

        EVP_PKEY_CTX_free(ctx);
        return decrypted;
    }
};

typedef std::chrono::microseconds microseconds;


// Klasse om tijd te meten want anders wordt de code onoverzichtelijk
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


// Werkt ook als je niet gelijktijdig bent, omdat de aes sleutel expliciet verstuurd wordt.
// De aes sleutel gaat over het netwerk (encrypted) maar als je RSA keypair ooit wordt gekraakt, kan de sleutel worden blootgelegd.

int main() {

	AsymmetricKeyExchange exchange;

	TimeMeasure tm;  

	std::cout << "Bob genereert RSA keypair...\n";

	tm.resetEvent();
	EVP_PKEY* pB_keypair = exchange.generate_rsa_keypair();
	microseconds rsaGenTime = tm.endEvent();

	std::cout << "RSA keypair van Bob gegenereerd in: "
		<< rsaGenTime.count() << " microseconden\n\n";


	// Publieke sleutel 
	EVP_PKEY* pB_public = pB_keypair;

	std::cout << "Alice genereert aes sleutel...\n";
	unsigned char aes_key[32];
	RAND_bytes(aes_key, 32);

	std::cout << "Alice encrypt aes sleutel met Bob zijn publieke sleutel...\n";

	tm.resetEvent();
	size_t encrypted_len = 0;
	unsigned char* encrypted_key = exchange.encrypt_aes_key(pB_public, aes_key, encrypted_len);
	microseconds encTime = tm.endEvent();

	if (!encrypted_key) {
		std::cout << "Encryptie mislukt\n";
		return 1;
	}

	std::cout << "Encryptie gelukt Tijd: "
		<< encTime.count() << " microseconden\n\n";


	std::cout << "Bob decrypt aes sleutel met prive sleutel...\n";

	tm.resetEvent();
	unsigned char* received_key = exchange.decrypt_aes_key(pB_keypair, encrypted_key, encrypted_len);
	microseconds decTime = tm.endEvent();

	if (!received_key) {
		std::cout << "Decryptie mislukt!\n";
		return 1;
	}

	std::cout << "Decryptie tijd: " << decTime.count() << " microseconden\n";

	if (memcmp(aes_key, received_key, 32) == 0)
		std::cout << "Beide robots hebben nu dezelfde aes sleutel!\n";
	else
		std::cout << "Sleutels komen niet overeen....\n";

	std::cout << "\nTotale tijd van alle events: "
		<< tm.getTotal().count() << " microseconden\n";

	// Cleanup
	OPENSSL_free(encrypted_key);
	OPENSSL_free(received_key);
	EVP_PKEY_free(pB_keypair);

	return 0;
}