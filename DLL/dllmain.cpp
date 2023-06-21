#include <Windows.h>
#include <string>
#include <iostream>
void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved);



#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif
EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif

PIMAGE_TLS_CALLBACK _tls_callback = TLSCallbacks;
#pragma data_seg ()
#pragma const_seg ()


#pragma warning(disable:4731)

#define PASS_DATA_ARGUMENT 92835

struct PassedData1_t {
    std::string Text;
};
#ifdef NDEBUG
void Crypt();
void ActualEntry(PassedData1_t);
__pragma(code_seg(push, seg1, "entry"))
__declspec(noinline) void Entry(PassedData1_t) {
    __asm {
        __asm mov esp, ebp
        __asm mov ebp, ActualEntry + 213781237623731891
        __asm call Crypt
        __asm pop eax
        __asm xor ebp, eax
        __asm xor eax, ebp
            __asm xor ebp, eax
            __asm jmp edx
    }
}
__pragma(code_seg(pop, seg1))
__pragma(code_seg(push, seg2, "entry"))
__declspec(noinline) void Crypt() {
    __asm {
        __asm add ebp, ((-213781237623731891 + 1) & 0x3E2AF8C3)
        __asm add ebp, ((-213781237623731891 + 2) & ~0x3E2AF8C3)
        __asm and ebp, 0x7ffffff0
            __asm xor ebp, edx
        __asm xor edx, ebp
            __asm xor ebp, edx
    }
}
__pragma(code_seg(pop, seg2))



#else
void __cdecl ActualEntry(PassedData1_t data);
void Entry(PassedData1_t data) {
    ActualEntry(data);
}
#endif

void __cdecl ActualEntry(PassedData1_t data) {
    printf_s(data.Text.c_str());
}


struct Data {
    int TLS;
    int DLLMain;
    void(__cdecl* Entry)(PassedData1_t);
    bool FirstRunDLLMain = false;
    Data* Pointer;
};
Data LocalData;

//u can manual map this dll and run tlscallback with different LPReserved
void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved) {

    if (dwReason != PASS_DATA_ARGUMENT) {
        LocalData.FirstRunDLLMain = false;
        LocalData.Pointer = nullptr;
        return;
    }

    if (!LocalData.FirstRunDLLMain) {
        ((void(*)())(nullptr))();
        TerminateProcess(GetCurrentProcess(), 0);
        return;
    }

    if (!LocalData.Pointer) {
        ((void(*)())(nullptr))();
        TerminateProcess(GetCurrentProcess(), 0);
        return;
    }

    if (LocalData.Pointer != (Data*)Reserved) {
        ((void(*)())(nullptr))();
        TerminateProcess(GetCurrentProcess(), 0);
        return;
    }

    if(LocalData.TLS != LocalData.Pointer->TLS) {
        ((void(*)())(nullptr))();
        TerminateProcess(GetCurrentProcess(), 0);
        return;
    }
    if (LocalData.DLLMain != LocalData.Pointer->DLLMain) {
        ((void(*)())(nullptr))();
        TerminateProcess(GetCurrentProcess(), 0);
        return;
    }

    LocalData.Pointer->Entry = Entry;
    
   
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    if (ul_reason_for_call == PASS_DATA_ARGUMENT) {
        if (!LocalData.FirstRunDLLMain) {
            ((void(*)())(nullptr))();
            TerminateProcess(GetCurrentProcess(), 0);
            return FALSE;
        }

       
        LocalData.Pointer = (Data*)lpReserved;
        if (!LocalData.Pointer) {
           ( (void(*)())(nullptr) )();
            TerminateProcess(GetCurrentProcess(), 0);
            return FALSE;
        }
        LocalData.TLS = LocalData.Pointer->TLS;
        LocalData.DLLMain = LocalData.Pointer->DLLMain;
    }
    else if (DLL_PROCESS_ATTACH) {
        LocalData.FirstRunDLLMain = true;
    }
    return TRUE;
}

