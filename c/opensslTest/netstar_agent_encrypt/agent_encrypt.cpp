#include "agent_encrypt.h"

#include <openssl/aes.h>  
#include <openssl/rand.h>  
#include <openssl/evp.h>  
#include <openssl/bio.h>  
#include <openssl/buffer.h>  


#define AES_KEY_LENGTH 32
#define AES_IV_LENGTH 16

#define PBKDF_ITER_TIME 55066



static void hexdump(
	FILE *f,
	const char *title,
	const unsigned char *s,
	int l)
{
	int n = 0;

	fprintf(f, "%s", title);
	for (; n < l; ++n) {
		if ((n % 16) == 0) {
			fprintf(f, "\n%04x", n);
		}
		fprintf(f, " %02x", s[n]);
	}

	fprintf(f, "\n");
}



agent_encrypt::agent_encrypt()
{
	char material2[] =
	{
		'0', '1', '2', '3', '4', '5', '6', '7',
		'0', '1', '2', '3', '4', '5', '6', '7',
		'1', 'b', 'c', 'd', 'e', 'f', 'g', 'i',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i',
	};

	m_material2 = std::string(material2,sizeof material2);
}



agent_encrypt * agent_encrypt::Instance()
{
	static agent_encrypt enc = agent_encrypt();
	return &enc;
}

void agent_encrypt::Set_material(const std::string & material)
{
	m_material2 = material;
}

std::string agent_encrypt::AES_encrypt(const std::string & input)
{

	if (input.length()>MAX_ENCRYPT_LENGTH)
	{
		return std::string();
	}

	std::string salt_input = FillSalt(input);

	std::string material1 = Get_material1();
	std::string material2 = Get_material2();

	unsigned char digest[AES_KEY_LENGTH + AES_IV_LENGTH];
	PKCS5_PBKDF2_HMAC(material1.c_str(), material1.length(), (unsigned char*)material2.c_str(), material2.length(), PBKDF_ITER_TIME, EVP_sha256(), AES_KEY_LENGTH + AES_IV_LENGTH, digest);

	hexdump(stdout, "== enc digest ==",
		digest,
		AES_KEY_LENGTH + AES_IV_LENGTH);


	AES_KEY         key;
	AES_set_encrypt_key(digest, AES_KEY_LENGTH * 8, &key);


	size_t cipherlen = salt_input.length();
	if (0 != cipherlen % 16)
	{
		cipherlen = (cipherlen / 16 + 1) * 16;
	}
	unsigned char* ciphertext = new unsigned char[cipherlen]();

	AES_cbc_encrypt((unsigned char*)salt_input.c_str(),
		ciphertext,
		salt_input.length(),
		&key,
		digest+ AES_KEY_LENGTH,
		AES_ENCRYPT);

	std::string out = Base64Encode(std::string((char*)ciphertext, cipherlen));

	memset(digest, 0, AES_KEY_LENGTH + AES_IV_LENGTH);
	memset(ciphertext, 0, cipherlen);

	delete[] ciphertext;
	return out;
}

std::string agent_encrypt::AES_decrypt(const std::string & input)
{

	if (ENCRYPTED_DATA_LENGTH != input.length())
	{
		return std::string();
	}

	std::string deBaseStr = Base64Decode(input);


	std::string material1 = Get_material1();
	std::string material2 = Get_material2();
	unsigned char digest[AES_KEY_LENGTH + AES_IV_LENGTH];
	PKCS5_PBKDF2_HMAC(material1.c_str(), material1.length(), (unsigned char*)material2.c_str(), material2.length(), PBKDF_ITER_TIME, EVP_sha256(), AES_KEY_LENGTH + AES_IV_LENGTH, digest);

	hexdump(stdout, "== dec digest ==",
		digest,
		AES_KEY_LENGTH + AES_IV_LENGTH);

	AES_KEY         key;
	AES_set_decrypt_key(digest, AES_KEY_LENGTH * 8, &key);


	size_t cipherlen = deBaseStr.length();
	if (0 != cipherlen % 16)
	{
		cipherlen = (cipherlen / 16 + 1) * 16;
	}

	unsigned char* ciphertext = new unsigned char[cipherlen]();
	AES_cbc_encrypt((unsigned char*)deBaseStr.c_str(),
		ciphertext,
		deBaseStr.length(),
		&key,
		digest + AES_KEY_LENGTH,
		AES_DECRYPT);

	std::string out = PeelSalt(std::string((char*)ciphertext, cipherlen));


	memset(digest, 0, AES_KEY_LENGTH + AES_IV_LENGTH);
	memset(ciphertext, 0, cipherlen);

	delete[] ciphertext;
	return out;
}

std::string agent_encrypt::Get_rand(unsigned int randomlength)
{
	unsigned char* salt = new unsigned char[randomlength]();

	RAND_pseudo_bytes(salt, randomlength);

	std::string out = std::string((char*)salt, randomlength);

	delete[] salt;
	return out;
}



std::string agent_encrypt::Get_material1()
{
	static char  material1[] =
	{
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i',
		'0', '1', '2', '3', '4', '5', '6', '7',
		'0', '1', '2', '3', '4', '5', '6', '7',
	};
	return std::string(material1, sizeof material1);
}

std::string agent_encrypt::Get_material2()
{
	char material2[] =
	{
		'0', '1', '2', '3', '4', '5', '6', '7',
		'0', '1', '2', '3', '4', '5', '6', '7',
		'1', 'b', 'c', 'd', 'e', 'f', 'g', 'i',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i',
	};
	return m_material2;
}

std::string agent_encrypt::FillSalt(const std::string & input)
{
	unsigned int saltlen = MAX_ENCRYPT_LENGTH - input.length();
	unsigned char* salt = new unsigned char[saltlen]();

	RAND_pseudo_bytes(salt, saltlen);

	std::string out = std::string(1, saltlen+1) + std::string((char*)salt, saltlen) + input;

	delete[] salt;
	return out;
}

std::string agent_encrypt::PeelSalt(const std::string & input)
{
	size_t pos = (size_t)input[0];

	if (pos>= input.length())
	{
		return std::string();
	}
	return input.substr(pos,input.length()- pos);
}

std::string agent_encrypt::Base64Encode(const std::string & input)
{
	BIO * bmem = NULL;
	BIO * b64 = NULL;
	BUF_MEM * bptr = NULL;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input.c_str(), input.length());
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	std::string output = std::string(bptr->data, bptr->length);
	BIO_free_all(b64);

	return output;
}

std::string agent_encrypt::Base64Decode(const std::string & input)
{
	BIO * b64 = NULL;
	BIO * bmem = NULL;
	char * buffer = new char[AES_KEY_LENGTH + AES_IV_LENGTH]();

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem = BIO_new_mem_buf(input.c_str(), input.length());
	bmem = BIO_push(b64, bmem);
	BIO_read(bmem, buffer, input.length());

	BIO_free_all(bmem);

	std::string output = std::string(buffer, AES_KEY_LENGTH + AES_IV_LENGTH);


	delete[] buffer;

	return output;
}

