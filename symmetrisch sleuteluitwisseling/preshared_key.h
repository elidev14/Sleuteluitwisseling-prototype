#pragma once
#include <vcruntime_string.h>
class preshared_key
{
	// beide partijen hebben dezelfde sleutel
	unsigned char shared_key[32]; // AES 256 key 

	public:
	// beide robots krijgen dezelfde key
		preshared_key(unsigned char* key) {
		memcpy(shared_key, key, 32);
	}

	void send_message(const char* msg) {

	}

	void receive_message(unsigned char* encrypted) {

	}
};

