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

#pragma comment(lib,"ws2_32.lib")

enum LockType {
	None = 0,
	Mutex = 1
};

using Ms = std::chrono::milliseconds;
using us = std::chrono::microseconds;

#define PORT 4080


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