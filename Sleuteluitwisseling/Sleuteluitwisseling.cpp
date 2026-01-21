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
#include <functional>


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
	int amount = 0;
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


void HandleServerMessages(
	std::stop_token st,
	SOCKET client)
{

	ClientHandler handler;
	while (!st.stop_requested())
	{
		std::string msg = handler.ReadLine(client);
		if (msg.empty())
			break;

		std::cout << msg << '\n';
	}
}

void RunClientHandshake(SOCKET sock)
{
	ECDHKeyExchange ecdh;
	ecdh.generate_keypair();

	// Send public key length
	size_t pub_len = 0;
	unsigned char* pub = ecdh.get_public_key(pub_len);
	send(sock, (char*)&pub_len, sizeof(pub_len), 0);

	// Send public key bytes (RAW)
	send(sock, (char*)pub, pub_len, 0);

	// Receive server public key length
	size_t server_len = 0;
	recv(sock, (char*)&server_len, sizeof(server_len), MSG_WAITALL);

	// Receive server public key
	std::vector<unsigned char> server_pub(server_len);
	recv(sock, (char*)server_pub.data(), server_len, MSG_WAITALL);


	// Compute shared secret
	size_t secret_len = 0;
	unsigned char* secret =
		ecdh.compute_shared_secret(
			server_pub.data(),
			server_pub.size(),
			secret_len
		);

	std::cout << "[Client] Shared secret established\n";
}



void HandleClient(std::stop_token st, SOCKET client, std::string username)
{

	RunClientHandshake(client);

	std::jthread serverThread(HandleServerMessages, client);

	char buffer[128];

	while (!st.stop_requested())
	{
		snprintf(buffer, sizeof(buffer), "MSG %s\n", username.c_str());
		send(client, buffer, strlen(buffer), 0);
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	serverThread.request_stop();

	shutdown(client, SD_BOTH);

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

		SOCKET client = cH.ConnectClient(PORT);

		clients.push_back({
			client,
			std::jthread(HandleClient, client, name)
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
	TimeMeasure::microSeconds genTime = tm.endEvent();

	return 0;
}