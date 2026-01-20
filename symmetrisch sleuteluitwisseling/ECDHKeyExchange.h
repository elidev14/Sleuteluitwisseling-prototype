#ifndef ECDHKEYEXCHANGE_HPP
#define ECDHKEYEXCHANGE_HPP
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>

class ECDHKeyExchange {
private:
	EVP_PKEY* keypair;  // Bevat zowel public als private key

public:
	ECDHKeyExchange() : keypair(nullptr) {}

	~ECDHKeyExchange() {
		if (keypair) EVP_PKEY_free(keypair);
	}

	// Genereer ECDH keypair (X25519 curve)
	bool generate_keypair() {
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
		if (!ctx) return false;

		if (EVP_PKEY_keygen_init(ctx) <= 0) return false;
		if (EVP_PKEY_keygen(ctx, &keypair) <= 0) return false;

		EVP_PKEY_CTX_free(ctx);
		return true;
	}

	// Haal de public key op (als bytes)
	unsigned char* get_public_key(size_t& len_out) {

		// vraag lengte op
		size_t pub_len = 0;
		EVP_PKEY_get_raw_public_key(keypair, nullptr, &pub_len);

		// Alloceren
		unsigned char* pub = (unsigned char*)OPENSSL_malloc(pub_len);

		// public key ophalen
		if (!EVP_PKEY_get_raw_public_key(keypair, pub, &pub_len)) {
			OPENSSL_free(pub);
			return nullptr;
		}

		len_out = pub_len;
		return pub;
	}


	// Bereken shared secret met de public key van de ander
	unsigned char* compute_shared_secret(const unsigned char* other_pub, size_t other_len, size_t& secret_len_out) {

		// Laad de andere public key in een EVP_PKEY
		EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, other_pub, other_len);
		if (!peer) return nullptr;

		// Context
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(keypair, nullptr);
		if (!ctx) return nullptr;

		if (EVP_PKEY_derive_init(ctx) <= 0) return nullptr;
		if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) return nullptr;

		// Shared secret lengte bepalen
		EVP_PKEY_derive(ctx, nullptr, &secret_len_out);

		unsigned char* secret = (unsigned char*)OPENSSL_malloc(secret_len_out);

		// Shared secret berekenen
		if (EVP_PKEY_derive(ctx, secret, &secret_len_out) <= 0) {
			OPENSSL_free(secret);
			return nullptr;
		}

		EVP_PKEY_free(peer);
		EVP_PKEY_CTX_free(ctx);
		return secret;
	}
};
#endif