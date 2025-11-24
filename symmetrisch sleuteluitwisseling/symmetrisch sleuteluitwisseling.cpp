// symmetrisch sleuteluitwisseling.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <chrono>
#include "preshared_key.h"
#include "DiffieHellman.h"



int main() {


	// Pre shared key methode: Het probleem hier is hoe ze nou aan de key komen
	unsigned char key[32];
	RAND_bytes(key, 32);

	preshared_key pA(key);
	preshared_key pB(key);

	// Nu kunnen ze communiceren
	pA.send_message("Hallo Robot B");


	// DiffieHellman methode
	DiffieHellman DH_pA, DH_pB;

	// Beide genereren keypair
	DH_pA.generate_keypair();
	DH_pB.generate_keypair();

	// keys uitwisselen
	auto keypA = DH_pA.get_public_key();
	auto keypB = DH_pB.get_public_key();

	// Stap 3: Beide berekenen ZELFDE shared secret
	auto secretA = DH_pA.compute_shared_secret(keypA);
	auto secretB = DH_pB.compute_shared_secret(keypB);


	std::cout << "Robot A en B hebben nu dezelfde AES sleutel zonder deze te versturen!" << std::endl;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
