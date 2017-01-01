// opensslTest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <string.h>  
#include <iostream>  
#include <fstream>


#include "../netstar_agent_encrypt/netstar_agent_encrypt.h"

using namespace std;

#define FILE_NAME "test/abc1.dat"

int main()
{

	std::ifstream fin(FILE_NAME, std::ios::binary);	

	if (fin.is_open())
	{
		cout << "file is open " << endl;
	}
	else
	{
		cout << "file not open " << endl;

		std::string rands = ENCRYPT_GetRandom();

		std::ofstream fout(FILE_NAME, std::ios::binary);
		fout.write(rands.c_str(), rands.length());
		fout.close();
		fin.open(FILE_NAME, std::ios::binary);
	}


	std::string material((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
	fin.close();

	ENCRYPT_SetMaterial(material);



	while (true)
	{

		std::string org = "dongyu";
		std::string encOut = ENCRYPT_Aes_encrypt(org);

		cout << encOut.c_str() << endl;

		std::string decOut = ENCRYPT_Aes_decrypt(encOut);

		cout << decOut.c_str() << endl;

		if (org != decOut)
		{

			cout << "org != decOut "<< endl;
		}

	}





	getchar();

	return 0;
}


