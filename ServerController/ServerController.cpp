// ServerController.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define WIN32_LEAN_AND_MEAN 

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include "ProtocolHandler.h"
#include <thread>
#include <mutex>
#include <chrono>
#include <vector>
#include <random>
#include "ECDHKeyExchange.h"

#pragma comment(lib,"ws2_32.lib")

enum LockType {
	None = 0,
	Mutex = 1
};


struct SessionContext {
	size_t token;
};

using Ms = std::chrono::milliseconds;
using us = std::chrono::microseconds;

#define PORT 4080


void RunServerHandshake(SOCKET client)
{
	ECDHKeyExchange ecdh;
	ecdh.generate_keypair();

	// Receive client public key length
	size_t client_len = 0;
	recv(client, (char*)&client_len, sizeof(client_len), MSG_WAITALL);

	// Receive client public key
	std::vector<unsigned char> client_pub(client_len);
	recv(client, (char*)client_pub.data(), client_len, MSG_WAITALL);

	// Send server public key length
	size_t pub_len = 0;
	unsigned char* pub = ecdh.get_public_key(pub_len);
	send(client, (char*)&pub_len, sizeof(pub_len), 0);

	//Send server public key
	send(client, (char*)pub, pub_len, 0);

	// Compute shared secret
	size_t secret_len = 0;
	unsigned char* secret =
		ecdh.compute_shared_secret(
			client_pub.data(),
			client_pub.size(),
			secret_len
		);

	std::cout << "[Server] Shared secret established\n";
}



SOCKET SetupServer()
{

	SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (server == INVALID_SOCKET)
	{
		/* error */
	}

	if (bind(server, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		/* error */
	}


	if (listen(server, SOMAXCONN) == SOCKET_ERROR)
	{

		/* error */
	}

	std::cout << "Server listening... \n";
	return server;
}

void HandleClient(SOCKET client)
{
	RunServerHandshake(client);

	while (true)
	{

		std::string line = ProtocolHandler::readLine(client);
		if (line.empty()) break;

		ProtocolHandler::handleCommand(client, line);
	}

	closesocket(client);
	std::cout << "Client disconnected\n";
}


int main(void)
{
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

	//Setup the server
	SOCKET server = SetupServer();

	//Continuously running loop
	while (true)
	{
		//Accepts new client
		SOCKET client = accept(server, nullptr, nullptr);

		//breaks if client 
		if (client == INVALID_SOCKET)
		{
			int err = WSAGetLastError();

			// accept interrupted by shutdown 
			if (err == WSAENOTSOCK || err == WSAEINVAL)
				break;

			// keep server alive
			std::cerr << "accept failed: " << err << "\n";
			continue;
		}
		std::cout << "A connection has been made!\n";
		std::thread(HandleClient, client).detach();
	}



	std::cout << "Closing server..\n";

	closesocket(server);
	WSACleanup();


	return 0;
}