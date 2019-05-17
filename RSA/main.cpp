#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#if __cplusplus < 201703L
namespace fs = std::experimental::filesystem;
#else
namespace fs = std::filesystem;
#endif

#include "integer.h"
#include "rsa.h"
#include "pem.h"
#include "osrng.h"
#include "files.h"

struct PublicKeyData
{
	CryptoPP::RSA::PublicKey	publicKey;
	CryptoPP::Integer			gcd;
};

struct PrivateKeyData
{
	CryptoPP::RSA::PrivateKey	privateKey;
	size_t						fileIndex;
};

std::vector<PublicKeyData> load_public_keys()
{
	std::vector<PublicKeyData> publicKeyDatas;

	for (auto i = 0; i < 8; ++i)
	{
		try
		{
			std::string fileName = "public-keys\\" + std::to_string(i + 1) + ".pem";
			CryptoPP::FileSource input(fileName.c_str(), true);

			CryptoPP::RSA::PublicKey publicKey;
			PEM_Load(input, publicKey);

			publicKeyDatas.push_back({ publicKey, 1 });

			for (auto k = 0; k < i; ++k)
			{
				const auto gcd = CryptoPP::Integer::Gcd(publicKeyDatas.at(i).publicKey.GetModulus(), publicKeyDatas.at(k).publicKey.GetModulus());
				if (gcd != 1)
				{
					publicKeyDatas.at(i).gcd = gcd;
					publicKeyDatas.at(k).gcd = gcd;
				}
			}
		}
		catch (const CryptoPP::Exception& ex)
		{
			std::cerr << ex.what() << std::endl;
		}
	}

	return publicKeyDatas;
}

CryptoPP::Integer calculate_private_exponent(const CryptoPP::Integer& n, const CryptoPP::Integer& e, const CryptoPP::Integer& gcd)
{
	const auto& p = gcd;
	const auto q = n / p;

	const auto phi = (p - 1) * (q - 1);
	const auto d = e.InverseMod(phi);

	return d;
}

std::vector<PrivateKeyData> calculate_private_keys(const std::vector<PublicKeyData>& publicKeyDatas)
{
	std::vector<PrivateKeyData> privateKeys;

	for (size_t i = 0; i < publicKeyDatas.size(); ++i)
	{
		if (publicKeyDatas[i].gcd == 1)
			continue;

		const auto n = publicKeyDatas[i].publicKey.GetModulus();
		const auto e = publicKeyDatas[i].publicKey.GetPublicExponent();
		const auto d = calculate_private_exponent(n, e, publicKeyDatas[i].gcd);

		CryptoPP::InvertibleRSAFunction params;
		params.Initialize(n, e, d);

		privateKeys.push_back({CryptoPP::RSA::PrivateKey(params), (i + 1) });
	}

	return privateKeys;
}

void save_private_keys(const std::vector<PrivateKeyData>& privateKeyDatas)
{
	fs::create_directory("private-keys");
	//CreateDirectory("private-keys", nullptr);

	for (auto& privateKeyData : privateKeyDatas)
	{
		try
		{
			std::string privateKey_str;
			CryptoPP::StringSink sink(privateKey_str);

			PEM_Save(sink, privateKeyData.privateKey);

			std::ofstream privateKey_file("private-keys\\" + std::to_string(privateKeyData.fileIndex) + ".pem");
			privateKey_file << privateKey_str;
			privateKey_file.close();
		}
		catch (const CryptoPP::Exception& ex)
		{
			std::cerr << ex.what() << std::endl;
		}
	}
}

void decrypt_messages(const std::vector<PrivateKeyData>& privateKeyDatas)
{
	CryptoPP::AutoSeededRandomPool rng;

	for (auto i = 0; i < 8; ++i)
	{
		std::string file = "messages\\" + std::to_string(i + 1) + ".bin";

		std::string encrypted;
		CryptoPP::FileSource input(file.c_str(), true, new CryptoPP::StringSink(encrypted));

		for (auto& privateKeyData : privateKeyDatas)
		{
			if (privateKeyData.fileIndex == (i + 1))
			{
				CryptoPP::RSAES_PKCS1v15_Decryptor decryptor(privateKeyData.privateKey);

				std::string decrypted;
				decrypted.resize(encrypted.size());

				const auto result = decryptor.Decrypt(rng, (unsigned char*)encrypted.data(), encrypted.size(),
					(unsigned char*)decrypted.data());

				if (result.isValidCoding)
				{
					std::cout << decrypted << std::endl;
				}
				else
				{
					std::cerr << "Invalid coding" << std::endl;
				}

				break;
			}
		}
	}
}

int main(int argc, char* argv[])
{
	auto publicKeyDatas = load_public_keys();
	std::cout << "Loaded " << publicKeyDatas.size() << " public keys." << std::endl;

	auto privateKeyDatas = calculate_private_keys(publicKeyDatas);
	std::cout << "Found " << privateKeyDatas.size() << " private keys." << std::endl << std::endl;

	save_private_keys(privateKeyDatas);

	std::cout << "Decrypting messages.." << std::endl << std::endl;
	decrypt_messages(privateKeyDatas);
	

	getchar();

	return 0;
}
