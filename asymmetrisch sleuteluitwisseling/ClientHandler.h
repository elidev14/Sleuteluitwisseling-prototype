#ifndef CLIENTHANDLER_HPP
#define CLIENTHANDLER_HPP
#include <WinSock2.h>
#include <string>
#include <cstring>
#include <iostream>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <cstdio>

class ClientHandler
{
private: 
	void VerifyConnection(const SOCKET& client, const std::string& clientName);

public:
	std::string ReadLine(const SOCKET &client);
	SOCKET ConnectClient(const int PORT, const std::string& clientName);
};


#endif

