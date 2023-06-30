
#include "pe_file.hpp"

#include <iostream>
#include <Windows.h>

int main()
{
	HWND console = GetConsoleWindow();
	
	RECT rc;
	GetWindowRect(console, &rc);

	MoveWindow(console, 50, 50, 1000, 1000, TRUE);
	
	const aes_key aes_hard_key =
	{
		0xbc, 0x64, 0x7c, 0xa1, 0x5f, 0xea, 0x00, 0xc5,
		0xd5, 0x38, 0xca, 0x94, 0xb7, 0x72, 0x0e, 0x49,
		0x24, 0xad, 0xd8, 0xb0, 0xa9, 0x81, 0x27, 0x0d,
		0x03, 0xf4, 0x34, 0xef, 0x41, 0x55, 0x03, 0x74
	};

	const aes_iv aes_hard_iv =
	{
		0x43, 0x19, 0xdf, 0x5d, 0x46, 0x7d, 0x5f, 0x77, 
		0xb2, 0x75, 0xef, 0xe2, 0xd4, 0x78, 0x60, 0xfd
	};

	aes_buffer aes_hard_buffer;
	memcpy(aes_hard_buffer.key, aes_hard_key, sizeof(aes_key));
	memcpy(aes_hard_buffer.iv, aes_hard_iv, sizeof(aes_iv));
	
	printf("-- decrypting hollow exe --\n");
	pe_file encrypted_file(aes_hard_buffer);
	encrypted_file.load("G:\\Hacking\\Games\\MapleStory\\sources\\Cute Trainer (Free)\\Release\\Cute Trainer_e.exe");
	encrypted_file.update();
	
	unsigned int pid = encrypted_file.execute();

	if (pid)
	{
		printf("-- decrypting hollow dll --\n");
		pe_file encrypted_dll(aes_hard_buffer);
		encrypted_dll.load("G:\\Hacking\\Games\\MapleStory\\sources\\Cute Trainer (Free)\\Release\\datdll_e.dll");
		encrypted_dll.update();
		
		if (!encrypted_dll.inject(pid))
			printf("inject failed\n");
	}
	else
	{
		printf("execute failed\n");
	}
	
	std::cout << "End of program.\n" << std::endl;
	std::cin.ignore();
	std::cin.get();
	return 0;
}