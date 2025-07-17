/* DEMO FOR KERNEL DRIVER (INCLUDES CSGO BUNNY HOP)*/
#define CSGO_CHEAT


#include<iostream>
#include<Windows.h>
#include<TlHelp32.h>

#include "csgo_offsets/client_dll.hpp"
#include "csgo_offsets/offsets.hpp"
#include "csgo_offsets/buttons.hpp"
using namespace cs2_dumper;

#ifdef CSGO_CHEAT
    #define PROCESSNAME L"cs2.exe"
#else
    #define PROCESSNAME L"notepad.exe"
#endif 


void PrintModuleNames(DWORD dwProcessId)
{
    
    MODULEENTRY32 lpModuleEntry = { 0 };
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
    if (!hSnapShot)	return;

    lpModuleEntry.dwSize = sizeof(lpModuleEntry);
    BOOL bModule = Module32First(hSnapShot, &lpModuleEntry);

    while (bModule)
    {
        std::printf("Current Module: %s\n", lpModuleEntry.szModule);

        bModule = Module32Next(hSnapShot, &lpModuleEntry);
    }

    CloseHandle(hSnapShot);
}

//define some helper functions
uintptr_t get_module_base_address(DWORD procId, const wchar_t* modName);
DWORD get_pid(const wchar_t* procname);

namespace driver {
    namespace codes {
        // Attaches driver to target process
        constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); // all CTL_CODE codes under 0x800 are reserved for windows 
        // Read Memory
        constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        // Write Memory
        constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG write_ignore_read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }

    // Request (structure shared between usermode and kernel)
    struct Request {
        HANDLE process_id;

        PVOID target_address;
        PVOID buffer;

        SIZE_T size;
        SIZE_T returnsize;
    };

    bool attach_to_process(HANDLE driver_handle, const DWORD pid) {
        Request request;
        request.process_id = reinterpret_cast<HANDLE>(pid);
        // Use device io control
        return DeviceIoControl(driver_handle, codes::attach, &request, sizeof(request), &request, sizeof(request), nullptr, nullptr);
    }
    bool read_memory(HANDLE driver_handle, uintptr_t target_address, LPVOID buffer,SIZE_T size) {
        Request request;
        request.target_address = (PVOID)target_address;
        request.buffer = (PVOID)buffer;
        request.size = size;
        // Use device io control
        return DeviceIoControl(driver_handle, codes::read, &request, sizeof(request), &request, sizeof(request), nullptr, nullptr);
    }

    void write_memory(HANDLE driver_handle, uintptr_t target_address, LPVOID buffer, SIZE_T size) {
        Request request;
        request.target_address = (PVOID)target_address;
        request.buffer = (PVOID)buffer;
        request.size = size;
        // Use device io control
        DeviceIoControl(driver_handle, codes::write, &request, sizeof(request), &request, sizeof(request), nullptr, nullptr);
    }
}

int main()
{
	std::cout << "PO COOL DRIVER\n";
    const wchar_t* procname = PROCESSNAME;
    const DWORD pid = get_pid(procname);
    if (!pid) {
        wprintf(L"failed to find: %ls\n", procname);
        std::cin.get();
        return 1;
    }

    //opens a handle to the driver
    const HANDLE driver_handle = CreateFileW(L"\\\\.\\BigBallsDriver", GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (driver_handle == INVALID_HANDLE_VALUE) {
        printf("could not create a driver handle\n");
        std::cin.get();
    }
    if (driver::attach_to_process(driver_handle, pid) == true) {
        printf("attached to process succcesfully\n");
#ifdef CSGO_CHEAT


        if (const uintptr_t client = get_module_base_address(pid, L"client.dll"); client != 0) {
            printf("client.dll found\n");
            while (true) {
                if (GetAsyncKeyState(VK_END))
                    break;

                uintptr_t localplayerpawn = 0;
                driver::read_memory(driver_handle, client + offsets::client_dll::dwLocalPlayerPawn, &localplayerpawn, sizeof(uintptr_t));
                if (localplayerpawn == 0)
                    continue;

                UINT32 flags;
                driver::read_memory(driver_handle, localplayerpawn + schemas::client_dll::C_BaseEntity::m_fFlags, &flags, sizeof(UINT32));

                const bool in_air = flags & (1 << 0);
                const bool space_pressed = GetAsyncKeyState(VK_SPACE);
                DWORD force_jump;
                driver::read_memory(driver_handle, client + buttons::jump, &force_jump, sizeof(DWORD));
                
                int random_ass_number = 65537;
                int random_ass_number2 = 256;
                if (space_pressed && in_air) {
                    Sleep(10);
                    driver::write_memory(driver_handle, client + buttons::jump, &random_ass_number,sizeof(int));
                }
                else if (space_pressed && !in_air) {
                    driver::write_memory(driver_handle, client + buttons::jump, &random_ass_number2, sizeof(int));
                }
                else if (!space_pressed && force_jump == random_ass_number) {
                    driver::write_memory(driver_handle, client + buttons::jump, &random_ass_number2, sizeof(int));
                }
            }
        }
        else {
            printf("client.dll not found\n");
        }

#else
        if (const uintptr_t client = get_module_base_address(pid, L"Notepad.exe"); client != 0) {
            UINT32 randombytes = 0;
            driver::write_memory(driver_handle, client + 0x129050, &randombytes, sizeof(UINT32));
            std::cout << "randomm bytes read:" << randombytes << '\n';
        }
#endif
    }

    CloseHandle(driver_handle);

    std::cin.get();

	return 0;
}



DWORD get_pid(const wchar_t* procname)
{
    DWORD procId = 0;
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hsnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W procentry = { sizeof(procentry) };
        if (Process32FirstW(hsnap, &procentry)) {
            do {
                if (!_wcsicmp(procentry.szExeFile, procname)) {
                    procId = procentry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hsnap, &procentry));
        }
    }
    CloseHandle(hsnap);
    return procId;
}


uintptr_t get_module_base_address(DWORD procId, const wchar_t* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32FirstW(hSnap, &modEntry))
        {
            do
            {
                if (!_wcsicmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32NextW(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}