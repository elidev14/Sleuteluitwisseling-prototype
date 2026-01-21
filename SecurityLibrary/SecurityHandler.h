#pragma once

#ifndef  SecurityHandler_HPP
#define SecurityHandler_HPP

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <array>
#include <stdexcept>
#include <vector>
#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
namespace SecurityLibrary
{

	struct GcmPacket {
		std::array<unsigned char, 12> iv;
		std::vector<unsigned char> ct;
		std::array<unsigned char, 16> tag;
	};

	class SecurityHandler
	{
	public:
		static std::array<unsigned char, 32>DeriveKeyHKDF(const unsigned char* secret, size_t secret_len);

		static GcmPacket AesGcmEncrypt(const std::array<unsigned char, 32>& key, const unsigned char* pt, int pt_len);

		static bool AesGcmDecrypt(const std::array<unsigned char, 32>& key, const GcmPacket& in, std::vector<unsigned char>& pt_out);

	};
}
#endif // ! SecurityHandler_HPP



