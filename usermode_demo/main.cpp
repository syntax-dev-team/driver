#include<iostream>
#include<Windows.h>
#include<TlHelp32.h>

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
    const wchar_t* procname = L"notepad.exe";
    const DWORD pid = get_pid(procname);
    if (!pid) {
        wprintf(L"failed to find: %ls\n", procname);
        std::cin.get();
        return 1;
    }

    //opens a handle to the driver
    const HANDLE driver_handle = CreateFileW(L"\\\\.\\\BigBallsDriver", GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (driver_handle == INVALID_HANDLE_VALUE) {
        printf("could not create a driver handle\n");
        std::cin.get();
    }
    if (driver::attach_to_process(driver_handle, pid) == true) {
        printf("attached to process succcesfully\n");
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
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!_wcsicmp((wchar_t*)modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}