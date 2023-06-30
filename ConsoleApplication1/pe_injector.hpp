#pragma once

#include "pe_structs.hpp"

#include <Windows.h>

#include <functional>
#include <vector>

typedef struct _section_finalize_data
{
	unsigned char* address;
	unsigned char* aligned_address;
	unsigned __int32 size;
	unsigned __int32 characteristics;
	unsigned __int32 last;
} section_finalize_data;

namespace work
{
	bool relocate_base(unsigned int image_base, nt_header* nt_headers);
	bool build_import_table(unsigned int image_base, nt_header* nt_headers, decltype(&LoadLibraryA) fnLoadLibraryA, decltype(&GetProcAddress) fnGetProcAddress);
	bool execute_tls(unsigned int image_base, nt_header* nt_headers);
	bool execute_entry_point(unsigned int image_base, nt_header* nt_headers);
}

typedef struct _manual_map_info
{
	unsigned int image_base;
	nt_header* nt_headers;
	
	decltype(&LoadLibraryA) fnLoadLibraryA;
	decltype(&GetProcAddress) fnGetProcAddress;

	decltype(&work::relocate_base) relocate_base;
	decltype(&work::build_import_table) build_import_table;
	decltype(&work::execute_tls) execute_tls;
	decltype(&work::execute_entry_point) execute_entry_point;
} manual_map_info;

class pe_injector
{
public:
	pe_injector();
	~pe_injector();
	
	bool remote_load_library_by_name(unsigned int process_id, const std::string& library_name);

	bool remote_load_library(unsigned int process_id, std::vector<unsigned char>& file_data);
	bool local_load_library(std::vector<unsigned char>& file_data);

private:
	void set_privileges();

	unsigned char* allocate_image_base(nt_header* nt_headers, bool remote);
	unsigned char* allocate_manual_func(unsigned char* destination, void* source, std::size_t size);

	bool write_headers(unsigned char* image_base, nt_header* nt_headers, std::vector<unsigned char>& file_data, bool remote);
	bool write_sections(unsigned char* image_base, nt_header* nt_headers, std::vector<unsigned char>& file_data, bool remote);
	
	unsigned char* vallocate(unsigned int address, std::size_t size, bool remote, bool reserve = false);
	unsigned char* vallocate(unsigned char* address, std::size_t size, bool remote, bool reserve = false);
	bool vfree(unsigned char* address, std::size_t size, bool remote, bool decommit = false);
	bool vprotect(unsigned char* address, std::size_t size, unsigned int protect, unsigned int* old_protect, bool remote);

	bool write_memory(void* destination, void* source, std::size_t size, bool remote);
	bool write_zero_memory(void* destination, std::size_t length, bool remote);
	
private:
	HANDLE process_handle;
};