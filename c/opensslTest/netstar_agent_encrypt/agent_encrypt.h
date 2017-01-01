#pragma once

#include <string>


#define MAX_ENCRYPT_LENGTH 47

#define ENCRYPTED_DATA_LENGTH 64

class agent_encrypt
{
public:
	

	static agent_encrypt* Instance();

	void Set_material(const std::string& material);


	std::string AES_encrypt(const std::string& input);
	std::string AES_decrypt(const std::string& input);


	std::string Get_rand(unsigned int randomlength = 32);


private:
	agent_encrypt();

	std::string Get_material1();
	std::string Get_material2();

	std::string FillSalt(const std::string& input);
	std::string PeelSalt(const std::string& input);

	std::string Base64Encode(const std::string& input);

	std::string Base64Decode(const std::string& input);

	std::string m_material2;
};

