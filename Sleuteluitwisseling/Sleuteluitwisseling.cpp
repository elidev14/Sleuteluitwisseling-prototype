#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <cstring>
#include <iostream>
#include <chrono>
#include "TimeMeasure.h"
#include "ECDHKeyExchange.h"
#include <winsock2.h>
#include <string>
#include <thread>
#include <windows.h>
#include <format>
#include "ClientHandler.h"
#include <mutex>
#include <numeric>
#include <vector>
#include <latch>
//#include "SecurityHandler.h"
#include "tcphelpers.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 4080

/*Sources

My github: https://github.com/elidev14/UDPChat

For socket client-server
https://www.tallyhawk.net/WinsockExamples/
https://beej.us/guide/bgnet/html/#client-server-background
*/

using namespace std::chrono_literals;



std::mutex statsMutex;

//List of totaltimes
std::vector<TimeMeasure::microSeconds> handshakeTimes;

struct UserData {
	std::string username;
	int amount = 0;
};

struct ClientContext {
	SOCKET socket;
	std::jthread thread;
};


struct HandshakeResult {
	TimeMeasure::microSeconds total;
	std::array<unsigned char, 32> key; // AES-256 key
};

UserData SetupRobot()
{
	std::string name = "TESTBOT";
	int amount;

	UserData userData;

	//std::cout << "What name do you want to give the robots?\nName: ";
	//std::getline(std::cin, name);
	userData.username = name;

	std::cout << "How many bots do you want to spawn?\nAmount: ";
	std::cin >> amount;
	userData.amount = amount;



	std::string emp;
	std::getline(std::cin, emp);


	return userData;
}



HandshakeResult RunClientHandshake(SOCKET sock, std::string username)
{

	TimeMeasure tm;

	tm.resetEvent();
	ECDHKeyExchange ecdh;
	ecdh.generate_keypair();
	TimeMeasure::microSeconds kpGenTime = tm.endEvent();

	tm.resetEvent();
	size_t pub_len = 0;
	unsigned char* pub = ecdh.get_public_key(pub_len);
	TimeMeasure::microSeconds pubTime = tm.endEvent();

	send(sock, (char*)&pub_len, sizeof(pub_len), 0);

	tm.resetEvent();
	send(sock, (char*)pub, pub_len, 0);

	// Receive server public key length
	size_t server_len = 0;
	recv(sock, (char*)&server_len, sizeof(server_len), MSG_WAITALL);

	// Receive server public key
	std::vector<unsigned char> server_pub(server_len);
	recv(sock, (char*)server_pub.data(), server_len, MSG_WAITALL);
	TimeMeasure::microSeconds rcvPubKeyTime = tm.endEvent();

	tm.resetEvent();
	// Compute shared secret
	size_t secret_len = 0;
	unsigned char* secret = ecdh.compute_shared_secret(
		server_pub.data(),
		server_pub.size(),
		secret_len
	);
	TimeMeasure::microSeconds computeSharedKeyTime = tm.endEvent();



	auto sessionKey = SecurityLibrary::SecurityHandler::DeriveKeyHKDF(secret, secret_len);

	auto total = tm.getTotal();


	/*std::cout << "[Client] Shared secret established\n";*/


	//std::cout << "\n======= ROBOT: " << username << " =======\n" << "Handshake timing:\n"
	//	<< "  - Keypair generation:    " << kpGenTime << "\n"
	//	<< "  - Get public key:        " << pubTime << "\n"
	//	<< "  - Receive server pubkey: " << rcvPubKeyTime << "\n"
	//	<< "  - Compute shared secret: " << computeSharedKeyTime << "\n"
	//	<< "  - total:                 " << total << "\n";

	// Return both time and key
	HandshakeResult result;
	result.total = total;
	result.key = sessionKey;

	return result;
}



void HandleClient(std::stop_token st, SOCKET client, std::string username, std::latch& done) {
	try {
		// Krijg BEIDE de tijd EN de key terug
		auto handshakeResult = RunClientHandshake(client, username);

		// Update stats met de tijd
		{
			std::lock_guard lock(statsMutex);
			handshakeTimes.push_back(handshakeResult.total);
		}

		// Gebruik de key voor encryptie
		auto& key = handshakeResult.key;

		// Stuur encrypted PING bericht
		std::string message = "PING";
		auto encryptedOut = SecurityLibrary::SecurityHandler::AesGcmEncrypt(
			key,
			(unsigned char*)message.data(),
			(int)message.size()
		);

		if (!tcphelpers::SendGcmPacket(client, encryptedOut)) {
			std::cerr << "[Client] Failed to send GCM packet\n";
			closesocket(client);
			done.count_down();
			return;
		}

		//std::cout << "[Client] Sent encrypted: " << message << "\n";

		// Ontvang encrypted response
		SecurityLibrary::GcmPacket responseIn{};
		if (!tcphelpers::RecvGcmPacket(client, responseIn)) {
			std::cerr << "[Client] Failed to receive GCM packet\n";
			closesocket(client);
			done.count_down();
			return;
		}

		// Decrypt de response
		std::vector<unsigned char> decryptedResponse;
		if (!SecurityLibrary::SecurityHandler::AesGcmDecrypt(key, responseIn, decryptedResponse)) {
			std::cerr << "[Client] GCM decrypt failed\n";
			closesocket(client);
			done.count_down();
			return;
		}

		std::string reply(decryptedResponse.begin(), decryptedResponse.end());
		//std::cout << "[Client] Decrypted response: " << reply << "\n";

		shutdown(client, SD_BOTH);
		closesocket(client);
		//std::cout << "[Client] Disconnected\n";

	}
	catch (const std::exception& e) {
		std::cerr << "[Client] Exception: " << e.what() << "\n";
		closesocket(client);
	}

	done.count_down();
}


int main() {

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

	UserData data = SetupRobot();

	ClientHandler cH;

	std::vector<ClientContext> clients;
	clients.reserve(data.amount);

	std::latch done(data.amount);

	for (int i = 0; i < data.amount; i++)
	{
		std::string name = std::format("{} {}", data.username, i);

		SOCKET client = cH.ConnectClient(PORT);

		clients.push_back({
			client,
			std::jthread(HandleClient, client, name, std::ref(done))
			});
	}

	done.wait();

	/*while (true)
	{

		std::string input;

		std::cout << "Send message: ";

		std::getline(std::cin, input);

		std::transform(input.begin(), input.end(), input.begin(), ::toupper);

		if (input == "QUIT")
		{

			ExitClients(clients);
			clients.clear();
			break;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}*/
	std::cout << "Clients exiting server..\n";

	WSACleanup();

	auto total = std::accumulate(
		handshakeTimes.begin(),
		handshakeTimes.end(),
		std::chrono::microseconds{ 0 }
	);

	auto avg = total / handshakeTimes.size();
	auto min = *std::min_element(handshakeTimes.begin(), handshakeTimes.end());
	auto max = *std::max_element(handshakeTimes.begin(), handshakeTimes.end());

	std::cout << "\n\n========= ECDH =========\n";
	std::cout << "Amount robots used: " << data.amount << "\n";
	std::cout << "\Total time execution: " << total << "\n";
	std::cout << "\Min time of key exchangement: " << min << "\n";
	std::cout << "\Average time of key exchangement: " << avg << "\n";
	std::cout << "\Max time of key exchangement: " << max << "\n";



	std::string t;

	std::getline(std::cin, t);


	return 0;
}