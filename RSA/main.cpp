#include <string>
#include <iostream>
#include <fstream>
#include <map>
#include <Windows.h>

#include "integer.h"
#include "rsa.h"
#include "pem.h"
#include "osrng.h"
#include "files.h"

/* Configuration Part */
std::map<std::string, std::string> files =
{
	{ "1.bin", "1.pem" },
	{ "2.bin", "2.pem" },
	{ "3.bin", "3.pem" },
	{ "4.bin", "4.pem" },
	{ "5.bin", "5.pem" },
	{ "6.bin", "6.pem" },
	{ "7.bin", "7.pem" },
	{ "8.bin", "8.pem" }
};

const std::string publicKeyFolder = "public-keys\\";
const std::string privateKeyFolder = "private-keys\\";
const std::string encryptedMessageFolder = "messages\\";
/* End Configuration */


struct FileData
{
	CryptoPP::RSA::PublicKey	publicKey;
	CryptoPP::Integer			gcd;
	std::string					keyFileName;
};


std::vector<FileData> load_public_keys()
{
	std::vector<FileData> publicKeyDatas;

	for (auto& filePair : files)
	{
		try
		{
			CryptoPP::FileSource input((publicKeyFolder + filePair.second).c_str(), true);
			CryptoPP::RSA::PublicKey publicKey;

			PEM_Load(input, publicKey);

			FileData pkData = { publicKey, 1, filePair.second };

			// check for common GCD with existing keys
			for (auto& publicKeyData : publicKeyDatas)
			{
				const auto gcd = CryptoPP::Integer::Gcd(pkData.publicKey.GetModulus(), publicKeyData.publicKey.GetModulus());
				if (gcd != 1)
				{
					pkData.gcd = gcd;
					publicKeyData.gcd = gcd;
				}
			}

			publicKeyDatas.push_back(pkData);
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
	// calculate p, q
	const auto& p = gcd;
	const auto q = n / p;

	// calculate phi of n, d
	const auto phi = (p - 1) * (q - 1);
	const auto d = e.InverseMod(phi);

	return d;
}

std::map<std::string, CryptoPP::RSA::PrivateKey> generate_private_keys(const std::vector<FileData>& vFileData)
{
	std::map<std::string, CryptoPP::RSA::PrivateKey> privateKeyData;

	for (auto& fileData : vFileData)
	{
		if (fileData.gcd == 1)
			continue;

		const auto n = fileData.publicKey.GetModulus();
		const auto e = fileData.publicKey.GetPublicExponent();
		const auto d = calculate_private_exponent(n, e, fileData.gcd);

		// Init private key and save into the map
		CryptoPP::InvertibleRSAFunction params;
		params.Initialize(n, e, d);

		privateKeyData.insert({ fileData.keyFileName, CryptoPP::RSA::PrivateKey(params) });
	}

	return privateKeyData;
}

void save_private_keys(const std::map<std::string, CryptoPP::RSA::PrivateKey>& privateKeyDatas)
{
	CreateDirectory(privateKeyFolder.c_str(), nullptr);

	for (auto& privateKeyData : privateKeyDatas)
	{
		try
		{
			// save private keys in .pem format
			CryptoPP::FileSink fileSink((privateKeyFolder + privateKeyData.first).c_str(), true);
			PEM_Save(fileSink, privateKeyData.second);
		}
		catch (const CryptoPP::Exception& ex)
		{
			std::cerr << ex.what() << std::endl;
		}
	}
}

void decrypt_messages(const std::map<std::string, CryptoPP::RSA::PrivateKey>& privateKeyDatas)
{
	CryptoPP::AutoSeededRandomPool rng;

	for (auto& filePair : files)
	{
		std::string encrypted;
		CryptoPP::FileSource input((encryptedMessageFolder + filePair.first).c_str(), true, new CryptoPP::StringSink(encrypted));

		// check if private key exists for encrypted file
		auto privateKeyData = privateKeyDatas.find(filePair.second);
		if (privateKeyData != privateKeyDatas.end())
		{
			CryptoPP::RSAES_PKCS1v15_Decryptor decryptor(privateKeyData->second);

			std::string decrypted;
			decrypted.resize(encrypted.size());

			const auto result = decryptor.Decrypt(rng, (unsigned char*)encrypted.data(), encrypted.size(),
				(unsigned char*)decrypted.data());

			std::cout << (result.isValidCoding ? decrypted : "Invalid coding") << std::endl;
		}
		else
		{
			std::cerr << "Missing part for: " << filePair.first << std::endl << std::endl;
		}
	}
}

int main()
{
	auto publicKeyDatas = load_public_keys();
	std::cout << "Loaded " << publicKeyDatas.size() << " public keys." << std::endl;

	auto privateKeyDatas = generate_private_keys(publicKeyDatas);
	std::cout << "Found " << privateKeyDatas.size() << " private keys." << std::endl << std::endl;

	std::cout << "Decrypting messages.." << std::endl << std::endl;
	decrypt_messages(privateKeyDatas);

	std::cout << "Saving private keys to : " << privateKeyFolder << "..." << std::endl << std::endl;
	save_private_keys(privateKeyDatas);

	std::cout << "DONE! Press any key...";

	getchar();

	return 0;
}
