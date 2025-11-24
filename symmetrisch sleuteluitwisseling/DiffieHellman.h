#pragma once
#include <openssl/types.h>
// Beide robots genereren gezamenlijk een sleutel
// ZONDER dat ze die sleutel over het netwerk sturen!

class DiffieHellman {
	BIGNUM* private_key;
	BIGNUM* public_key;

public:
	void generate_keypair() {
		// Genereer private key
		// Bereken public key 
	}

	unsigned char* compute_shared_secret(BIGNUM* other_public) {
		// Bereken shared
		// Beide robots krijgen dezelkfde uitkomst
	}

	BIGNUM* get_public_key()
	{
	  //retouneer public key
	}
	
};
