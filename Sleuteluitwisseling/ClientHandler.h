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

public:
	std::string ReadLine(const SOCKET &client);
	SOCKET ConnectClient(const int PORT);
};


#endif

