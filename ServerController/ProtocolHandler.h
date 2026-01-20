
#ifndef PROTOCOLHANDLER_HPP
#define PROTOCOLHANDLER_HPP

#include <string>
#include <WinSock2.h>
#include <sstream>
#include <iostream>


class ProtocolHandler
{
	public:
		static void handleCommand(const SOCKET &client, const std::string& line);
		static std::string readLine(const SOCKET &client);
};



#endif // !PROTOCOLHANDLER_HPP

