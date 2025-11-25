#pragma once
#include <openssl/bn.h>
#include <openssl/rand.h>

class DiffieHellman {
private:
	BIGNUM* p;            // Prime (Dit is het priemgetal)
	BIGNUM* g;            // Generator (Dit is de basis van de exponentiatie)
	BIGNUM* private_key;  // Random geheim getal
	BIGNUM* public_key;   // g^private mod p

public:
	DiffieHellman()
	{
		//Moet nog vinden hoe ik hier aanmoet komen
		// Source: https://www.rfc-editor.org/rfc/rfc3526.html?page-3
		// heb 2048 bit nodig
		const char* prime_hex =
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF";

		p = BN_new();
		g = BN_new();
		private_key = BN_new();
		public_key = BN_new();

		BN_hex2bn(&p, prime_hex);

		// volgens rfc3526 is de generator 2
		BN_set_word(g, 2); 
	}

	// De deconstructor
	~DiffieHellman() {
		BN_free(p);
		BN_free(g);
		BN_free(private_key);
		BN_free(public_key);
	}

	// Beide partijen doen dit
	void generate_keypair() {
		BN_CTX* ctx = BN_CTX_new();

		// random 256 bit nummer
		// ALS dit publiek bereikbaar is dan is het gevaarlijk (Dus zorgen dat het niet publiek bereikbaar is!)
		BN_rand(private_key, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

		//g^private mod p
		BN_mod_exp(public_key, g, private_key, p, ctx);


		// Context cleanen
		BN_CTX_free(ctx);
	}

	// Bereken gedeelde geheim other_public ^ private mod p
	// Dit compute de shared key (de sharedkey zou hetzelfde moeten zijn als het dezelfde g en p heeft)
	// Shared key is gebasseerd op de publieke sleutel van a en b 
	unsigned char* compute_shared_secret(BIGNUM* other_public, size_t& secret_len_out) {
		BN_CTX* ctx = BN_CTX_new();
		BIGNUM* shared = BN_new();

		// other_public ^ private_key mod p
		BN_mod_exp(shared, other_public, private_key, p, ctx);

		// Omzetten naar bytes
		secret_len_out = BN_num_bytes(shared);
		unsigned char* secret = (unsigned char*)OPENSSL_malloc(secret_len_out);
		BN_bn2bin(shared, secret);

		BN_free(shared);
		BN_CTX_free(ctx);

		return secret; 
	}

	BIGNUM* get_public_key() {
		return public_key;
	}
};
