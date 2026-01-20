#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <cstring>
#include <iostream>
#include <chrono>
#include "TimeMeasure.h"
#include "ECDHKeyExchange.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <windows.h>
#include <ranges>
#include <algorithm>
#include "ClientHandler.h"


#pragma comment(lib, "ws2_32.lib")

#define PORT 4080

/*Sources

My github: https://github.com/elidev14/UDPChat

For socket client-server
https://www.tallyhawk.net/WinsockExamples/
https://beej.us/guide/bgnet/html/#client-server-background
*/

using namespace std::chrono_literals;

int ackID;


bool IsRobotSet = false;

struct UserData {
	std::string username;
};

UserData SetupRobot()
{
	std::string input;

	UserData userData;

	std::cout << "What is the name of this Robot?\nName: ";
	std::getline(std::cin, input);
	userData.username = input;

	return userData;
}



int main() {

	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		fprintf(stderr, "WSAStartup failed.\n");
		exit(1);
	}

	if (LOBYTE(wsaData.wVersion) != 2 ||
		HIBYTE(wsaData.wVersion) != 2)
	{
		fprintf(stderr, "Version 2.2 of Winsock not available.\n");
		WSACleanup();
		exit(2);
	}

	UserData data = SetupRobot();

	ClientHandler cH;

	SOCKET sock = cH.ConnectClient(PORT, data.username);

	char buffer[64];

	int ackID = 0;

	while (true)
	{
		ackID++;

		std::string input;

		std::cout << "Send message: ";

		std::getline(std::cin, input);

		std::transform(input.begin(), input.end(), input.begin(), ::toupper);

		if (input == "QUIT")
		{
			if (send(sock, "QUIT\n", 4, 0) == SOCKET_ERROR)
			{
				std::cout << "Failed to send message...\n";
				continue;
			}
			break;
		}
		else
		{
			snprintf(buffer, sizeof(buffer), "MSG %s %d\n", input, ackID);
		}

		if (send(sock, buffer, strlen(buffer), 0) == SOCKET_ERROR)
		{	
			std::cout << "Failed to send message...\n";
		}
		else
		{
			std::cout << "Message succefully send\n";
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}


	std::cout << "Exiting server..\n";
	closesocket(sock);
	WSACleanup();

	std::string t;

	std::getline(std::cin, t);

	TimeMeasure tm;
	std::cout << "=== ECDH with us of the X25519 curve ===\n";

	ECDHKeyExchange A, B;

	// Keypair generatie
	tm.resetEvent();
	A.generate_keypair();
	B.generate_keypair();
	TimeMeasure::microSeconds genTime = tm.endEvent();

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
	TimeMeasure::microSeconds compATime = tm.endEvent();

	tm.resetEvent();
	unsigned char* secB = B.compute_shared_secret(a_pub, a_pub_len, secB_len);
	TimeMeasure::microSeconds compBTime = tm.endEvent();

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


	return 0;
}