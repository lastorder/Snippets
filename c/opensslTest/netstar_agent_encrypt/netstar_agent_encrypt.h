#pragma once


#include <string>

#ifdef NETSTAR_AGENT_ENCRYPT_EXPORTS
#define AGENT_ENCRYPT_API __declspec(dllexport)
#else
#define AGENT_ENCRYPT_API __declspec(dllimport)
#endif



AGENT_ENCRYPT_API void ENCRYPT_SetMaterial(const std::string input);

AGENT_ENCRYPT_API std::string ENCRYPT_GetRandom();

AGENT_ENCRYPT_API std::string ENCRYPT_Aes_encrypt(const std::string input);

AGENT_ENCRYPT_API std::string ENCRYPT_Aes_decrypt(const std::string input);