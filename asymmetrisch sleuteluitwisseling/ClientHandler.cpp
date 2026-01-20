#include "ClientHandler.h"




SOCKET ClientHandler::ConnectClient(const int PORT, const std::string& clientName)
{
	const SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr); // localhost

	connect(sock, (sockaddr*)&addr, sizeof(addr));

	VerifyConnection(sock, clientName);

	return sock;
}

std::string ClientHandler::ReadLine(const SOCKET &client)
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

void ClientHandler::VerifyConnection(const SOCKET &sock, const std::string &clientName)
{

	char buffer[64];
	while (true)
	{

		snprintf(buffer, sizeof(buffer), "CONNECT %s\n", clientName);

		send(sock, buffer, strlen(buffer), 0);

		std::string line = ReadLine(sock);
		if (line == "OK")
		{
			std::cout << "You are connected to the server!\n";
			break;
		}

		std::cout << "Trying to connect with the server...\n";
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

}