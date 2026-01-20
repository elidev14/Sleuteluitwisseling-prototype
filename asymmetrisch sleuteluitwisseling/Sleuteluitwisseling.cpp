#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <cstring>
#include <iostream>
#include <chrono>
#include "TimeMeasure.h"
#include "ECDHKeyExchange.h"
#include <winsock2.h>
#include <string>
#include <thread>
#include <windows.h>
#include <format>
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
	int amount;
};

struct ClientContext {
	SOCKET socket;
	std::jthread thread;
};

UserData SetupRobot()
{
	std::string name;
	int amount;

	UserData userData;

	std::cout << "What name do you want to give the robots?\nName: ";
	std::getline(std::cin, name);
	userData.username = name;

	std::cout << "How many bots do you want to spawn?\nAmount: ";
	std::cin >> amount;
	userData.amount = amount;



	std::string emp;
	std::getline(std::cin, emp);
	std::cout << "Press enter to confirm.....";


	return userData;
}


void HandleClient(std::stop_token st, SOCKET client)
{

	char buffer[64];

	int ackID = 0;

	while (!st.stop_requested())
	{
		ackID++;

		snprintf(buffer, sizeof(buffer), "MSG %s %d\n", "test", ackID);

		if (send(client, buffer, strlen(buffer), 0) == SOCKET_ERROR)
		{
			std::cout << "Failed to send message...\n";
		}
		//else
		//{
		//	std::cout << "Message succefully send\n";
		//}

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}


	closesocket(client);
	std::cout << "Client disconnected\n";
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

	std::vector<ClientContext> clients;
	clients.reserve(data.amount);

	for (int i = 0; i < data.amount; i++)
	{
		std::string name = std::format("{} {}\n", data.username, i);

		SOCKET client = cH.ConnectClient(PORT, name);
		clients.push_back({
			client,
			std::jthread(HandleClient, client)
			});
	}


	while (true)
	{

		std::string input;

		std::cout << "Send message: ";

		std::getline(std::cin, input);

		std::transform(input.begin(), input.end(), input.begin(), ::toupper);

		if (input == "QUIT")
		{
			for (auto& client : clients)
			{
				if (send(client.socket, "QUIT\n", 4, 0) == SOCKET_ERROR)
				{
					std::cout << "Failed to send message...\n";
					continue;
				}
				client.thread.request_stop();
			}

			clients.clear();
			break;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	std::cout << "Exiting server..\n";
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