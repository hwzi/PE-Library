#pragma once

#include "pe_structs.hpp"

#include <fstream>
#include <vector>

enum class file_type
{
	dll,
	exe,
	unknown
};

typedef unsigned char aes_key[32];
typedef unsigned char aes_iv[16];

struct aes_buffer
{
	aes_key key;
	aes_iv iv;
};

class pe_file
{
public:
	pe_file(aes_buffer aes_data);
	
	void load(const std::string& file_path);
	void save(const std::string& file_path);

	bool update(bool decrypt = true);

	unsigned int execute();
	bool inject(unsigned int process_id = 0);

private:
	bool update_dos_header(bool decrypt);
	bool unpack_dos_header(dos_header* header);
	
	bool update_pe_header(bool decrypt);
	bool unpack_pe_header(pe_header* header);

	bool update_optional_header(bool decrypt);
	bool unpack_optional_header(optional_header* header);

	bool update_section_headers(bool decrypt);
	bool unpack_section_headers(section_header* header);
	
	bool update_exports(bool decrypt);
	bool unpack_exports(export_directory* directory);

	bool update_imports(bool decrypt);
	bool unpack_imports(import_descriptor* descriptor, bool decrypt);
	
	bool update_sections(bool decrypt);

	void crypt_buffer(unsigned char* buffer, std::size_t size, bool decrypt);
	unsigned __int64 rva_to_offset(unsigned __int64 rva);
	
	unsigned int launch_exe();
	bool inject_dll(unsigned int process_id);

	bool is_dll_file();
	bool is_exe_file();

private:
	file_type file_type;

	unsigned int section_count;
	std::vector<section_header> sections;

	std::pair<unsigned int, unsigned int> export_infos;
	std::pair<unsigned int, unsigned int> import_infos;

	std::size_t offset;
	std::vector<unsigned char> data;

	aes_buffer aes;
};