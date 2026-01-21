#include "ClientHandler.h"




SOCKET ClientHandler::ConnectClient(const int PORT)
{
	const SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr); // localhost

	connect(sock, (sockaddr*)&addr, sizeof(addr));

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
