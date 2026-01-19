// ServerController.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define WIN32_LEAN_AND_MEAN 

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>

#pragma comment(lib,"ws2_32.lib")

#define PORT 4080

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

	std::cout << "listening... \n";


	//Test
	SOCKET client = accept(server, nullptr, nullptr);

	const char* initMsg = "Hello.\n";
	size_t msgSize = strlen(initMsg);

	send(client, initMsg, msgSize, 0);

	char buffer[512];
	int bytesReceived = recv(client, buffer, sizeof(buffer) - 1, 0);

	if (bytesReceived > 0)
	{
		buffer[bytesReceived] = '\0';
		std::cout << "Received: " << buffer << std::endl;
	}
	else if (bytesReceived == 0)
	{
		std::cout << "Server closed the connection\n";
	}
	else
	{
		std::cerr << "recv failed\n";
	}

	closesocket(client);
	closesocket(server);
	WSACleanup();


	std::string t;

	std::getline(std::cin, t);
	return 0;
}