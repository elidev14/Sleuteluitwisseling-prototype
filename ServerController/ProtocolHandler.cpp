#include "ProtocolHandler.h"




//Handles input on server
void ProtocolHandler::handleCommand(const SOCKET &client, const std::string& line)
{
	std::istringstream iss(line);

	std::string cmd;
	iss >> cmd;

	if (cmd == "CONNECT")
	{
		std::string username;
		iss >> username;
		send(client, "OK\n", 3, 0);
		std::cout << username << " has connected!\n";
	}
	else if (cmd == "MSG")
	{
		std::string msg;
		std::getline(iss, msg);
		std::cout << "Message:" << msg << std::endl;
		send(client, "OK msg received\n", 3, 0);
	}
	else if (cmd == "QUIT")
	{
		closesocket(client);
	}
}

std::string ProtocolHandler::readLine(const SOCKET &client)
{
	std::string line;
	char c;

	while (true)
	{
		int r = recv(client, &c, 1, 0);
		if (r <= 0) return "";
		if (c == '\n') break;
		line += c;
	}
	return line;
}