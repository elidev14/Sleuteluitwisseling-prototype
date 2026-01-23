// SecurityHandler.cpp : Defines the functions for the static library.
//
#include "SecurityHandler.h"


/* 
 support sources: 
	https://manpages.debian.org/bullseye/libssl-doc/index.html, 
	https://github.com/openssl/openssl/blob/master/providers/implementations/kdfs/hkdf.c
	https://learn.microsoft.com/en-us/cpp/build/walkthrough-creating-and-using-a-static-library-cpp?view=msvc-170
*/

namespace SecurityLibrary
{

    std::array<unsigned char, 32> SecurityHandler::DeriveKeyHKDF(const unsigned char* secret, size_t secret_len)
	{
		std::array<unsigned char, 32> key{};

		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
		if (!ctx)
			throw std::runtime_error("HKDF ctx alloc failed");

		if (EVP_PKEY_derive_init(ctx) <= 0)
			throw std::runtime_error("HKDF init failed");

		if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0)
			throw std::runtime_error("HKDF set md failed");

		// No salt (acceptable for ECDHE can be added later)
		if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, (int)secret_len) <= 0)
			throw std::runtime_error("HKDF set key failed");

		const char info[] = "robot-session";
		if (EVP_PKEY_CTX_add1_hkdf_info(
			ctx,
			(unsigned char*)info,
			sizeof(info) - 1) <= 0)
			throw std::runtime_error("HKDF set info failed");

		size_t out_len = key.size();
		if (EVP_PKEY_derive(ctx, key.data(), &out_len) <= 0)
			throw std::runtime_error("HKDF derive failed");

		EVP_PKEY_CTX_free(ctx);
		return key;
	}


	 GcmPacket SecurityHandler::AesGcmEncrypt(const std::array<unsigned char, 32>& key, const unsigned char* pt, int pt_len)
	{
		GcmPacket out{};
		RAND_bytes(out.iv.data(), (int)out.iv.size());

		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)out.iv.size(), nullptr);
		EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), out.iv.data());

		out.ct.resize(pt_len);
		int len = 0, ct_len = 0;
		EVP_EncryptUpdate(ctx, out.ct.data(), &len, pt, pt_len);
		ct_len = len;

		EVP_EncryptFinal_ex(ctx, out.ct.data() + ct_len, &len);
		ct_len += len;
		out.ct.resize(ct_len);

		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)out.tag.size(), out.tag.data());
		EVP_CIPHER_CTX_free(ctx);
		return out;
	}

     bool SecurityHandler::AesGcmDecrypt(const std::array<unsigned char, 32>& key, const GcmPacket& in, std::vector<unsigned char>& pt_out)
	{
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)in.iv.size(), nullptr);
		EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), in.iv.data());

		pt_out.resize(in.ct.size());
		int len = 0, pt_len = 0;
		EVP_DecryptUpdate(ctx, pt_out.data(), &len, in.ct.data(), (int)in.ct.size());
		pt_len = len;

		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)in.tag.size(), (void*)in.tag.data());
		int ok = EVP_DecryptFinal_ex(ctx, pt_out.data() + pt_len, &len);
		EVP_CIPHER_CTX_free(ctx);

		if (ok <= 0) return false;
		pt_len += len;
		pt_out.resize(pt_len);
		return true;
	}
}

