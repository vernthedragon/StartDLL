#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
DWORD GetModuleBaseAddress(const char* lpszModuleName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    DWORD dwModuleBaseAddress = 0;
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 ModuleEntry = { 0 };
        ModuleEntry.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &ModuleEntry))
        {
            do
            {
                if (strcmp(ModuleEntry.szModule, lpszModuleName) == 0)
                {
                    dwModuleBaseAddress = (DWORD)ModuleEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnapshot, &ModuleEntry));
        }
        CloseHandle(hSnapshot);
    }
    return dwModuleBaseAddress;
}

using DLLMain_t = BOOL(APIENTRY*)(HMODULE dll, DWORD reason, LPVOID reserved);

struct PassedData1_t {
    std::string Text;
};

struct Data {
    int TLS;
    int DLLMain;
    void(__cdecl* Entry)(PassedData1_t);
};

#define PASS_DATA_ARGUMENT 92835

int main()
{
    PassedData1_t test;
    test.Text = "Hello World!\n";
    Data Passed;

    Passed.DLLMain = rand() % PASS_DATA_ARGUMENT;
    Passed.TLS = rand() % PASS_DATA_ARGUMENT;
    Passed.Entry = nullptr;
    HMODULE DLL = LoadLibraryA("DLL.dll");
    DWORD ModuleBase = GetModuleBaseAddress("DLL.dll");
    IMAGE_OPTIONAL_HEADER* OptionalHeader = &((IMAGE_NT_HEADERS*)(ModuleBase + ((IMAGE_DOS_HEADER*)ModuleBase)->e_lfanew))->OptionalHeader;
    DLLMain_t DLLMain = (DLLMain_t)(ModuleBase + OptionalHeader->AddressOfEntryPoint);

    DLLMain(DLL, PASS_DATA_ARGUMENT, &Passed);

    if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        IMAGE_TLS_DIRECTORY* Directory = (IMAGE_TLS_DIRECTORY*)(ModuleBase + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK* Callback = (PIMAGE_TLS_CALLBACK*)Directory->AddressOfCallBacks;
    
        while (Callback && *Callback) {
            (*Callback)((LPVOID)ModuleBase, PASS_DATA_ARGUMENT, &Passed);
            Callback++;
        }
    }



    if (Passed.Entry == nullptr)
        return 0;

    Passed.Entry(test);

    while (true) {

    }
}
