#include "netstar_agent_encrypt.h"

#include "agent_encrypt.h"

AGENT_ENCRYPT_API void ENCRYPT_SetMaterial(const std::string input)
{
	agent_encrypt::Instance()->Set_material(input);
}

AGENT_ENCRYPT_API std::string ENCRYPT_GetRandom()
{
	return agent_encrypt::Instance()->Get_rand();
}

AGENT_ENCRYPT_API std::string ENCRYPT_Aes_encrypt(const std::string input)
{
	return agent_encrypt::Instance()->AES_encrypt(input);
}

AGENT_ENCRYPT_API std::string ENCRYPT_Aes_decrypt(const std::string input)
{
	return agent_encrypt::Instance()->AES_decrypt(input);
}
