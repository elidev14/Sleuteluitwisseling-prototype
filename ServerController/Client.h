
#ifndef CLIENT_HPP
#include <WinSock2.h>
#include <WS2tcpip.h>
class Client
{
public:
	void Connect()
	{
		char buffer[512];

		SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(8080);
		inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

		connect(sock, (sockaddr*)&addr, sizeof(addr));

		send(sock, "Hi\n", 3, 0);
		recv(sock, buffer, sizeof(buffer), 0);
	}
};



#endif // !CLIENT_HPP

