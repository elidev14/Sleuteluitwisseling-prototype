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
#include "TimeMeasure.h"
#include "tcphelpers.h"
#include "SecurityHandler.h"

#pragma comment(lib,"ws2_32.lib")

enum LockType {
	None = 0,
	Mutex = 1
};


struct HandshakeResult {
	TimeMeasure::microSeconds total;
	std::array<unsigned char, 32> key; // AES-256 key
};


using Ms = std::chrono::milliseconds;
using us = std::chrono::microseconds;

#define PORT 4080


std::array<unsigned char, 32> RunServerHandshake(SOCKET client)
{
	ECDHKeyExchange ecdh;
	ecdh.generate_keypair();

	// Receive client public key length
	size_t client_len = 0;
	if (recv(client, (char*)&client_len, sizeof(client_len), MSG_WAITALL) <= 0) {
		throw std::runtime_error("recv client_len failed");
	}


	// Receive client public key
	std::vector<unsigned char> client_pub(client_len);
	if (recv(client, (char*)client_pub.data(), (int)client_len, MSG_WAITALL) <= 0) {
		throw std::runtime_error("recv client_pub failed");
	}

	// Send server public key length
	size_t pub_len = 0;
	unsigned char* pub = ecdh.get_public_key(pub_len);

	if (send(client, (char*)&pub_len, sizeof(pub_len), 0) == SOCKET_ERROR) {
		throw std::runtime_error("send pub_len failed");
	}

	//Send server public key
	if (send(client, (char*)pub, (int)pub_len, 0) == SOCKET_ERROR) {
		throw std::runtime_error("send pub failed");
	}


	// Compute shared secret
	size_t secret_len = 0;
	unsigned char* secret = ecdh.compute_shared_secret(client_pub.data(), client_pub.size(), secret_len);
	if (!secret || secret_len == 0) {
		throw std::runtime_error("compute_shared_secret failed");
	}


	auto sessionKey = SecurityLibrary::SecurityHandler::DeriveKeyHKDF(secret, secret_len);

	// Als compute_shared_secret OPENSSL_malloc gebruikt: vrijgeven:
	OPENSSL_free(secret);

	std::cout << "[Server] Shared secret established\n";
	return sessionKey;
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
		std::cerr << "[Server] Exception: " << "An error occured with the client" << "\n";
	}

	if (bind(server, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		std::cerr << "[Server] Exception: " << "An error occured with the client" << "\n";
	}


	if (listen(server, SOMAXCONN) == SOCKET_ERROR)
	{
		std::cerr << "[Server] Exception: " << "An error occured with the client" << "\n";
	}

	std::cout << "Server listening... \n";
	return server;
}

void HandleClient(SOCKET client)
{
	try {
		auto key = RunServerHandshake(client);

		SecurityLibrary::GcmPacket in{};

		if (!tcphelpers::RecvGcmPacket(client, in)) {
			std::cerr << "[Server] Failed to receive GCM packet\n";
			closesocket(client);
			return;
		}

		std::vector<unsigned char> pt;
		if (!SecurityLibrary::SecurityHandler::AesGcmDecrypt(key, in, pt)) {
			std::cerr << "[Server] GCM decrypt failed\n";
			closesocket(client);
			return;
		}

		std::string msg(pt.begin(), pt.end());
		std::cout << "[Server] Decrypted: " << msg << "\n";

		std::string reply = (msg == "PING") ? "PONG" : "ERR";
		auto out = SecurityLibrary::SecurityHandler::AesGcmEncrypt(key, (unsigned char*)reply.data(), (int)reply.size());
		tcphelpers::SendGcmPacket(client, out);

		// Daarna kun je sluiten of teruggaan naar readLine()
		closesocket(client);
		std::cout << "Client disconnected\n";
	}
	catch (const std::exception& e) {
		std::cerr << "[Server] Exception: " << e.what() << "\n";
		closesocket(client);
	}
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