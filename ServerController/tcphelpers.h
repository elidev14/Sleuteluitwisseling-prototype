#pragma once

#ifndef TCPHELPER_HPP
#define TCPHELPER_HPP
#include <WinSock2.h>
#include "SecurityHandler.h"

class tcphelpers
{
	//help: https://stackoverflow.com/questions/3847508/handling-tcp-streams

public:
	static bool RecvAll(SOCKET s, void* buf, int n) {
		char* p = (char*)buf;
		int got = 0;
		while (got < n) {
			int r = recv(s, p + got, n - got, 0);
			if (r <= 0) return false;
			got += r;
		}
		return true;
	}

	static bool SendAll(SOCKET s, const void* buf, int n) {
		const char* p = (const char*)buf;
		int sent = 0;
		while (sent < n) {
			int r = send(s, p + sent, n - sent, 0);
			if (r == SOCKET_ERROR) return false;
			sent += r;
		}
		return true;
	}

	static bool SendGcmPacket(SOCKET s, const SecurityLibrary::GcmPacket& p) {
		uint32_t iv_len = 12;
		uint32_t ct_len = (uint32_t)p.ct.size();
		if (!SendAll(s, &iv_len, sizeof(iv_len))) return false;
		if (!SendAll(s, p.iv.data(), 12)) return false;
		if (!SendAll(s, &ct_len, sizeof(ct_len))) return false;
		if (!SendAll(s, p.ct.data(), (int)ct_len)) return false;
		if (!SendAll(s, p.tag.data(), 16)) return false;
		return true;
	}

	static bool RecvGcmPacket(SOCKET s, SecurityLibrary::GcmPacket& p) {
		uint32_t iv_len = 0, ct_len = 0;
		if (!RecvAll(s, &iv_len, sizeof(iv_len))) return false;
		if (iv_len != 12) return false;
		if (!RecvAll(s, p.iv.data(), 12)) return false;

		if (!RecvAll(s, &ct_len, sizeof(ct_len))) return false;
		p.ct.resize(ct_len);
		if (!RecvAll(s, p.ct.data(), (int)ct_len)) return false;

		if (!RecvAll(s, p.tag.data(), 16)) return false;
		return true;
	}


};


#endif // !TCPHELPER_HPP
