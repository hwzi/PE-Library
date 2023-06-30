#pragma once

#include "pe_structs.hpp"

#include <Windows.h>

#include <string>
#include <vector>

class pe_process
{
public:
	pe_process();
	~pe_process();

	bool create_process(const std::string& command_line);
	bool hollow_process(std::vector<unsigned char>& file_data);

	void resume();

	HANDLE get_process_handle();
	unsigned int get_process_id();

private:
	bool unmap_view_of_section(unsigned int address);
	void* virtual_alloc(unsigned int address, std::size_t size);

	bool read_process_memory(void* destination, void* source, std::size_t size);
	bool write_process_memory(void* destination, void* source, std::size_t size);
	
	STARTUPINFOA startup_info;
	PROCESS_INFORMATION process_info;
};