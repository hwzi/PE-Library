#include "pe_injector.hpp"
#include "pe_structs.hpp"

namespace work
{
	bool relocate_base(unsigned int image_base, nt_header* nt_headers)
	{
		const unsigned int relocation_based_highlow = 3;

		unsigned int delta = image_base - nt_headers->optional_header.image_base;
		
		for (base_relocation* relocation =  reinterpret_cast<base_relocation*>(image_base + nt_headers->optional_header.data_directory[directory_entry_basereloc].virtual_address); relocation->virtual_address != 0;
			relocation = reinterpret_cast<base_relocation*>(reinterpret_cast<unsigned char*>(relocation) + relocation->block_size))
		{
			if (relocation->block_size >= sizeof(base_relocation))
			{
				unsigned char* destination = reinterpret_cast<unsigned char*>(image_base) + relocation->virtual_address;
				unsigned short* relocation_info = reinterpret_cast<unsigned short*>(reinterpret_cast<unsigned char*>(relocation) + sizeof(base_relocation));

				for (std::size_t i = 0; i < ((relocation->block_size - sizeof(base_relocation)) / sizeof(unsigned short)); i++)
					if (relocation_info[i] && ((relocation_info[i] >> 12) == relocation_based_highlow))
						*reinterpret_cast<unsigned int*>(image_base + relocation->virtual_address + (relocation_info[i] & 0x0FFF)) += delta;
			}
		}
		
		return true;
	}
	
	bool build_import_table(unsigned int image_base, nt_header* nt_headers, decltype(&LoadLibraryA) fnLoadLibraryA, decltype(&GetProcAddress) fnGetProcAddress)
	{
		const unsigned __int32 ordinal_flag_32 = 0x80000000;

		for (import_descriptor* descriptor = reinterpret_cast<import_descriptor*>(image_base + nt_headers->optional_header.data_directory[directory_entry_import].virtual_address); descriptor->characteristics != 0; descriptor++)
		{
			thunk_data* thunk = nullptr;

			if (descriptor->original_first_thunk)
				thunk = reinterpret_cast<thunk_data*>(image_base + descriptor->original_first_thunk);
			else
				thunk = reinterpret_cast<thunk_data*>(image_base + descriptor->first_thunk);

			HMODULE module = fnLoadLibraryA(reinterpret_cast<char*>(image_base + descriptor->name));

			if (!module)
				return false;

			for (FARPROC* function = reinterpret_cast<FARPROC*>(image_base + descriptor->first_thunk); thunk->data_address != 0; thunk++, function++)
			{
				if (thunk->ordinal & ordinal_flag_32)
				{
					*function = fnGetProcAddress(module, reinterpret_cast<char*>(thunk->ordinal & 0xFFFF));

				}
				else
				{
					unsigned char* function_name = reinterpret_cast<import_by_name*>(image_base + thunk->data_address)->name;
					*function = fnGetProcAddress(module, reinterpret_cast<char*>(function_name));
				}
			}
		}
		
		return true;
	}
	
	bool execute_tls(unsigned int image_base, nt_header* nt_headers)
	{
		if (!nt_headers->optional_header.data_directory[directory_entry_tls].size)
			return true;
		
		tls_callback_t* callback = reinterpret_cast<tls_callback_t*>(reinterpret_cast<tls_directory*>(image_base + nt_headers->optional_header.data_directory[directory_entry_tls].virtual_address)->callback_address);

		if (callback)
		{
			while (*callback)
			{
				(*callback)(reinterpret_cast<void*>(image_base), DLL_PROCESS_ATTACH, NULL);
				callback++;
			}
		}

		return true;
	}
	
	bool execute_entry_point(unsigned int image_base, nt_header* nt_headers)
	{
		if (!nt_headers->optional_header.entry_point_address)
			return false;

		typedef BOOL (APIENTRY* DllEntryPoint_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
		DllEntryPoint_t DllEntryPoint = reinterpret_cast<DllEntryPoint_t>(image_base + nt_headers->optional_header.entry_point_address);

		if (!DllEntryPoint)
			return false;

		return (DllEntryPoint(reinterpret_cast<HINSTANCE>(image_base), DLL_PROCESS_ATTACH, NULL) != FALSE);
	}
}

namespace remote
{
	bool __stdcall load_library(manual_map_info* manual_map)
	{	
		if (manual_map->image_base - manual_map->nt_headers->optional_header.image_base)
			if (!manual_map->relocate_base(manual_map->image_base, manual_map->nt_headers))
				return false;
		
		if (!manual_map->build_import_table(manual_map->image_base, manual_map->nt_headers, manual_map->fnLoadLibraryA, manual_map->fnGetProcAddress))
			return false;
		
		if (!manual_map->execute_tls(manual_map->image_base, manual_map->nt_headers))
			return false;

		return manual_map->execute_entry_point(manual_map->image_base, manual_map->nt_headers);
	}
}

pe_injector::pe_injector()
	: process_handle(NULL)
{
	
}

pe_injector::~pe_injector()
{
	
}

bool pe_injector::remote_load_library(unsigned int process_id, std::vector<unsigned char>& file_data)
{  
	this->set_privileges();

	this->process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
	
	if (!this->process_handle)
		return false;
	
	dos_header* dos_headers = reinterpret_cast<dos_header*>(file_data.data());
	nt_header* nt_headers = reinterpret_cast<nt_header*>(file_data.data() + dos_headers->pe_offset);
	
	if (nt_headers->optional_header.section_alignment & 1)
		return false;

	unsigned char* image_base = this->allocate_image_base(nt_headers, true);

	if (!image_base)
	{
		CloseHandle(this->process_handle);
		return false;
	}
	
	if (!this->write_headers(image_base, nt_headers, file_data, true))
	{
		this->vfree(image_base, 0, true);
		CloseHandle(this->process_handle);
		return false;
	}

	if (!this->write_sections(image_base, nt_headers, file_data, true))
	{
		this->vfree(image_base, 0, true);
		CloseHandle(this->process_handle);
		return false;
	}

	unsigned char* loader_memory = this->vallocate(static_cast<unsigned int>(0), sizeof(manual_map_info) + (0x1000 * 5) + 0x100, true);

	if (!loader_memory)
	{
		this->vfree(image_base, 0, true);
		CloseHandle(this->process_handle);
		return false;
	}

	manual_map_info manual_map;
	memset(&manual_map, 0, sizeof(manual_map_info));

	manual_map.image_base = reinterpret_cast<unsigned int>(image_base);
	manual_map.nt_headers = reinterpret_cast<nt_header*>(image_base + dos_headers->pe_offset);
	
	manual_map.fnLoadLibraryA = LoadLibraryA;
	manual_map.fnGetProcAddress = GetProcAddress;

	manual_map.relocate_base = decltype(&work::relocate_base)(this->allocate_manual_func(loader_memory + sizeof(manual_map_info) + 0x1000, work::relocate_base, 0x1000) + sizeof(manual_map_info));
	manual_map.build_import_table = decltype(&work::build_import_table)(this->allocate_manual_func(loader_memory + sizeof(manual_map_info) + 0x2000, work::build_import_table, 0x1000) + sizeof(manual_map_info));
	manual_map.execute_tls = decltype(&work::execute_tls)(this->allocate_manual_func(loader_memory + sizeof(manual_map_info) + 0x3000, work::execute_tls, 0x1000) + sizeof(manual_map_info));
	manual_map.execute_entry_point = decltype(&work::execute_entry_point)(this->allocate_manual_func(loader_memory + sizeof(manual_map_info) + 0x4000, work::execute_entry_point, 0x1000) + sizeof(manual_map_info));

	if (!this->write_memory(loader_memory, &manual_map, sizeof(manual_map_info), true))
	{
		this->vfree(image_base, 0, true);
		CloseHandle(this->process_handle);
		return false;
	}
	
	if (!this->write_memory(loader_memory + sizeof(manual_map_info), remote::load_library, 0x1000 - sizeof(manual_map_info), true))
	{
		this->vfree(image_base, 0, true);
		CloseHandle(this->process_handle);
		return false;
	}

	HANDLE thread_handle = CreateRemoteThread(this->process_handle, NULL, 0, LPTHREAD_START_ROUTINE(loader_memory + sizeof(manual_map_info)), loader_memory, 0, NULL);

	if (!thread_handle)
	{
		this->vfree(image_base, 0, true);
		CloseHandle(this->process_handle);
		return false;
	}

	WaitForSingleObject(thread_handle, INFINITE);

	CloseHandle(thread_handle);
	CloseHandle(this->process_handle);
	return true;
}

bool pe_injector::local_load_library(std::vector<unsigned char>& file_data)
{
	this->set_privileges();

	dos_header* dos_headers = reinterpret_cast<dos_header*>(file_data.data());
	nt_header* nt_headers = reinterpret_cast<nt_header*>(file_data.data() + dos_headers->pe_offset);
	
	if (nt_headers->optional_header.section_alignment & 1)
		return false;

	unsigned char* image_base = this->allocate_image_base(nt_headers, false);

	if (!image_base)
		return false;
	
	if (!this->write_headers(image_base, nt_headers, file_data, false))
	{
		this->vfree(image_base, 0, false);
		return false;
	}

	if (!this->write_sections(image_base, nt_headers, file_data, false))
	{
		this->vfree(image_base, 0, false);
		return false;
	}

	if (image_base - nt_headers->optional_header.image_base)
	{
		if (!work::relocate_base(reinterpret_cast<unsigned int>(image_base), nt_headers))
		{
			this->vfree(image_base, 0, false);
			return false;
		}
	}

	if (!work::build_import_table(reinterpret_cast<unsigned int>(image_base), nt_headers, LoadLibraryA, GetProcAddress))
	{
		this->vfree(image_base, 0, false);
		return false;
	}
		
	if (!work::execute_tls(reinterpret_cast<unsigned int>(image_base), nt_headers))
	{
		this->vfree(image_base, 0, false);
		return false;
	}

	if (!work::execute_entry_point(reinterpret_cast<unsigned int>(image_base), nt_headers))
	{
		this->vfree(image_base, 0, false);
		return false;
	}

	return true;
}

void pe_injector::set_privileges()
{
	HANDLE token_handle = NULL;

    if (OpenProcessToken(reinterpret_cast<HANDLE>(-1), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
    {
		TOKEN_PRIVILEGES tp;
		memset(&tp, 0, sizeof(TOKEN_PRIVILEGES));

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
 
        tp.Privileges[0].Luid.LowPart = 20;
        tp.Privileges[0].Luid.HighPart = 0;
 
        AdjustTokenPrivileges(token_handle, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(token_handle);
    }
}

unsigned char* pe_injector::allocate_image_base(nt_header* nt_headers, bool remote)
{
	unsigned char* image_base = this->vallocate(nt_headers->optional_header.image_base, nt_headers->optional_header.image_size, remote, true);

	if (!image_base)
	{
		image_base = this->vallocate(static_cast<unsigned int>(0), nt_headers->optional_header.image_size, remote, true);
	}

	return image_base;
}

unsigned char* pe_injector::allocate_manual_func(unsigned char* destination, void* source, std::size_t size)
{
	unsigned char* alloc = this->vallocate(destination, size, true);

	if (!alloc)
		return reinterpret_cast<unsigned char*>(0);

	if (!this->write_memory(destination, source, size, true))
		return reinterpret_cast<unsigned char*>(0);

	return alloc;
}

bool pe_injector::write_headers(unsigned char* image_base, nt_header* nt_headers, std::vector<unsigned char>& file_data, bool remote)
{
	unsigned char* headers = this->vallocate(image_base, nt_headers->optional_header.headers_size, remote);

	if (!headers)
		return false;

	return this->write_memory(headers, file_data.data(), nt_headers->optional_header.headers_size, remote);
}

bool pe_injector::write_sections(unsigned char* image_base, nt_header* nt_headers, std::vector<unsigned char>& file_data, bool remote)
{
	SYSTEM_INFO system_info;
	memset(&system_info, 0, sizeof(SYSTEM_INFO));

	GetNativeSystemInfo(&system_info);
	
	unsigned int optional_header_offset = reinterpret_cast<unsigned int>(&reinterpret_cast<nt_header*>(0)->optional_header);
	unsigned int optional_header_size = nt_headers->file_header.optional_header_size;

	section_header* section = reinterpret_cast<section_header*>(reinterpret_cast<unsigned char*>(nt_headers) + optional_header_offset + optional_header_size);

	for (std::size_t i = 0; i < nt_headers->file_header.section_count; i++, section++)
	{
		if (!section->raw_data_size)
		{
			unsigned int alignment = nt_headers->optional_header.section_alignment;

			if (alignment > 0)
			{
				unsigned char* section_base = this->vallocate(image_base + section->virtual_address, alignment, remote);

				if (!section_base)
					return false;

				if (!this->write_zero_memory(section_base, alignment, remote))
					return false;

				if (!remote)
					section->misc.physical_address = reinterpret_cast<unsigned int>(section_base);
			}
		}
		else
		{
			unsigned char* section_base = this->vallocate(image_base + section->virtual_address, section->misc.virtual_size, remote);

			if (!section_base)
				return false;
			
			std::size_t section_min_size = (section->raw_data_size < section->misc.virtual_size ? section->raw_data_size : section->misc.virtual_size);

			if (!this->write_memory(section_base, file_data.data() + section->raw_data_pointer, section_min_size, remote))
				return false;
			
			if (!remote)
				section->misc.physical_address = reinterpret_cast<unsigned int>(section_base);
		}
	}
	
	return true;
}

unsigned char* pe_injector::vallocate(unsigned int address, std::size_t size, bool remote, bool reserve)
{
	if (!remote)
		return reinterpret_cast<unsigned char*>(VirtualAlloc(reinterpret_cast<void*>(address), size, MEM_COMMIT | (reserve ? MEM_RESERVE : NULL), PAGE_EXECUTE_READWRITE));
	else
		return reinterpret_cast<unsigned char*>(VirtualAllocEx(this->process_handle, reinterpret_cast<void*>(address), size, MEM_COMMIT | (reserve ? MEM_RESERVE : NULL), PAGE_EXECUTE_READWRITE));
}

unsigned char* pe_injector::vallocate(unsigned char* address, std::size_t size, bool remote, bool reserve)
{
	if (!remote)
		return reinterpret_cast<unsigned char*>(VirtualAlloc(address, size, MEM_COMMIT | (reserve ? MEM_RESERVE : NULL), PAGE_EXECUTE_READWRITE));
	else
		return reinterpret_cast<unsigned char*>(VirtualAllocEx(this->process_handle, address, size, MEM_COMMIT | (reserve ? MEM_RESERVE : NULL), PAGE_EXECUTE_READWRITE));
}

bool pe_injector::vfree(unsigned char* address, std::size_t size, bool remote, bool decommit)
{
	if (!remote)
		return (VirtualFree(address, size, (decommit ? MEM_DECOMMIT : MEM_RELEASE)) != FALSE);
	else
		return (VirtualFreeEx(this->process_handle, address, size, (decommit ? MEM_DECOMMIT : MEM_RELEASE)) != FALSE);
}

bool pe_injector::vprotect(unsigned char* address, std::size_t size, unsigned int protect, unsigned int* old_protect, bool remote)
{
	if (!remote)
		return (VirtualProtect(address, size, protect, reinterpret_cast<unsigned long*>(old_protect)) != FALSE);
	else
		return (VirtualProtectEx(this->process_handle, address, size, protect, reinterpret_cast<unsigned long*>(old_protect)) != FALSE);
}

bool pe_injector::write_memory(void* destination, void* source, std::size_t size, bool remote)
{
	if (!remote)
		return (memcpy(destination, source, size) != nullptr);
	else
		return (WriteProcessMemory(this->process_handle, destination, source, size, NULL) != FALSE);
}

bool pe_injector::write_zero_memory(void* destination, std::size_t length, bool remote)
{
	unsigned char* buffer = new unsigned char[length];

	bool result = this->write_memory(destination, buffer, length, remote);

	delete[] buffer;
	return result;
}