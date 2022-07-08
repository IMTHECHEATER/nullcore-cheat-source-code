#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdlib.h>
#include "files.h"
#include "hooks.h"
#include <cstdio>
#include <vector>
#include <iostream>

void Resolve(HMODULE hMod);

class Page
{
public:
	Page() {};

	Page(int size, void* buffer)
	{
		this->ptr = (char*)VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		this->size = size;
	
		if (buffer) memcpy(this->ptr, buffer, size);
	}

	char* ptr;
	DWORD size;
};

Page Page_Signature, Page_CFG, Page_Blank;
HMODULE NCC;

DWORD WINAPI Handle_Entry3(LPVOID Entry3)
{
	using FuncType = void __stdcall(HMODULE, int, int, const char*, void*, void*, unsigned);
	((FuncType*)Entry3)(NCC, 4, 1, "cracked by vietcong909", Page_Blank.ptr, Page_Signature.ptr, Page_Signature.size);
	return 0;
}

DWORD WINAPI Handle_Entry(LPVOID Entry)
{
	using FuncType = void __stdcall();
	((FuncType*)Entry)();
	return 0;
}

DWORD WINAPI Handle_Entry2(LPVOID Entry2)
{
	using FuncType = void __stdcall(const char*, unsigned);
	((FuncType*)Entry2)(Page_CFG.ptr, Page_CFG.size);
	return 0;
}

void AwaitThread(HANDLE Thread)
{
	if (Thread)
		WaitForSingleObject(Thread, INFINITE);
	else
	{
		MessageBoxA(0, "Failed thread to Handle_Entry3", "Fatal error", NULL);
		ExitProcess(0);
	}	
}

#include <fstream>

DWORD WINAPI MainThread(LPVOID)
{
	AwaitThread(CreateThread(0, 0, Handle_Entry3, (char*)NCC + 0x2A0E0, 0, 0));
	AwaitThread(CreateThread(0, 0, Handle_Entry, (char*)NCC + 0x29F80, 0, 0));
	AwaitThread(CreateThread(0, 0, Handle_Entry, (char*)NCC + 0x29FF0, 0, 0));
	AwaitThread(CreateThread(0, 0, Handle_Entry2, (char*)NCC + 0x2A070, 0, 0));

	return TRUE;
}

struct __declspec(align(4)) struct_xordat
{
	BYTE key[20];   // 0x0
	size_t len;     // 0x14
	BYTE bites[];   // 0x18
};

struct __declspec(align(4)) struct_xorretn
{
	BYTE bFirst;
	BYTE gap1[3];
	DWORD len;
	char* alloc;
	BYTE key[20];
};

CJumpHook Hook_CPU;
CJumpHook Hook_Xor;
CJumpHook Hook_CreateWindow;

int _cdecl Hooked_Xor(int a1, char* a2);
int __stdcall Hooked_CPU();
void* __cdecl Hooked_CreateWindow(const char* idk);

BOOL WINAPI DllMain(HMODULE hMod, DWORD dwReason, LPVOID)
{
	if (dwReason != DLL_PROCESS_ATTACH)
		return true;

	PVOID FileBuffer = RebuiltDLL;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pDosHeader->e_lfanew);
	PVOID ExecutableImage = VirtualAlloc(NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(ExecutableImage, FileBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);

	PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) memcpy((PVOID)((LPBYTE)ExecutableImage + pSectHeader[i].VirtualAddress), (PVOID)((LPBYTE)FileBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData);

	NCC = (HMODULE)ExecutableImage;
	Resolve(NCC);

	Hook_Xor.Hook((char*)NCC + 0x61100L, &Hooked_Xor);
	Hook_CPU.Hook((char*)NCC + 0x98790, &Hooked_CPU);
	Hook_CreateWindow.Hook((char*)NCC + 0x65180, &Hooked_CreateWindow);

	DWORD* CPU1And3 = (DWORD*)((char*)NCC + 0x1b6180);
	DWORD& CPU2 = *(DWORD*)((char*)NCC + 0x162ab4);
	DWORD& CPU1 = CPU1And3[0];
	DWORD& CPU3 = CPU1And3[1];
	CPU3 = CPU2 = CPU1 = 0x69;
	
	Page_Signature = Page(0x36F, SignaturePage);
	Page_CFG = Page(0x1F5BF, NULL); // Leaving the CFG page blank tricks NCC into resetting all your "cloud configs"
	Page_Blank = Page(0x1000, NULL);

	uintptr_t Heartbeat[] = { 0x23fe9L, 0x2245dL, 0x2193dL, 0x20dddL, 0x20b44L, 0x1ec1bL, 0x1c4ebL };
	for (auto Flag : Heartbeat) memset((char*)NCC + Flag, 0x90, 10); /* Patch out loader heartbeat */

	*((char*)NCC + 0x32ADE + 0x1) = 0xE8; /* Patch the Cloud Sync Failed to Cloud Sync Successful */
	*((char*)NCC + 0x32ADE + 0x2) = 0x53; /* because it's funny */

	CreateThread(0, 0, MainThread, 0, 0, 0);

	return true;
}


void* __cdecl Hooked_CreateWindow(const char* idk)
{
	void* Wnd = 0;
	__asm mov Wnd, ecx

	typedef void* (__thiscall* Fn)(void*, const char*);
	auto old = (Fn)Hook_CreateWindow.Original();
	auto result = old(Wnd, idk);

	int wndTextLen = *(int*)((char*)idk + 48 + 4);

	if (wndTextLen == sizeof("Settings") * 2 || wndTextLen == sizeof("Player Manager") * 2)
	{
		int size = wndTextLen == sizeof("Settings") * 2 ? 247 : 485;

		typedef void* (__thiscall* FnAddTab)(void* Parent, const char* Text);
		auto AddTab = (FnAddTab)((char*)NCC + 0x66020);
		auto NewTab = AddTab(Wnd, "info");
		
		typedef void* (__thiscall* FnUrl)(char* Dat, void* Parent, int x, int y, int w, int h, int u4, LPCSTR szText, const char* szUrl, int a10, int a11);
		static auto CreateTextElement = (FnUrl)((char*)NCC + 0x64910);

		typedef DWORD* (__thiscall* FnLogo)(DWORD* thisptr, void* a2, int a3, int a4, int a5, int a6, int a7);
		auto CreateIcon = (FnLogo)((char*)NCC + 0x64A50);
		CreateIcon(new DWORD[0x90u], NewTab, size - 32, 16 + 32, 64, 64, 2);
		CreateTextElement(new char[0xBC], NewTab, size - 95/*152*/ + /*(*/93/* * 2)*/, 16 + 64 + 4 + 32 + 8, 0, 0, 5, "------------", "https://nullcoreproject.net", 1, -1);
		CreateTextElement(new char[0xBC], NewTab, size - 93, 16 + 64 + 12 + 32, 0, 0, 4, "Mistakes Nullified Multiplied", "https://nullcoreproject.net", 0, -1);
		CreateTextElement(new char[0xBC], NewTab, size - 190, 16 + 64 + 38 + 32, 190 * 2, 14, 4, "Cracked by Bot ", "https://youtu.be/dQw4w9WgXcQ", 0, -1);
		CreateTextElement(new char[0xBC], NewTab, size - 70, 16 + 64 + 56 + 32, 70 * 2, 14, 4, "Click here for funnies", "https://youtu.be/dQw4w9WgXcQ", 0, -1);
		CreateTextElement(new char[0xBC], NewTab, size - 105, 16 + 64 + 56 + 32 + 18, 105 * 2, 14, 4, "Click here for awesome Discord", "https://discord.gg/86uZSTxDDw", 0, -1);
	}

	return Wnd;
}

int _cdecl Hooked_Xor(int a1, char* a2)
{
	static auto OriginalFn = (decltype(Hooked_Xor)*)(Hook_Xor.Original());
	auto Retn = OriginalFn(a1, a2);
	unsigned char XorKey[0x14] = { 0x92, 0xE3, 0xE9, 0xBA, 0x15, 0xB9, 0x0B, 0x4E, 0x7C, 0xE1, 0xCC, 0xBD, 0x57, 0xB1, 0x79, 0x35, 0xD3, 0xCC, 0x14, 0x8E };
	memcpy(a2, XorKey, 0x14);
	return Retn;
}

int __stdcall Hooked_CPU()
{
	int Result = ((decltype(Hooked_CPU)*)Hook_CPU.Original())();

	DWORD* CPU1And3 = (DWORD*)((char*)NCC + 0x1b6180);
	DWORD& CPU2 = *(DWORD*)((char*)NCC + 0x162ab4);
	DWORD& CPU1 = CPU1And3[0];
	DWORD& CPU3 = CPU1And3[1];
	CPU1 = 0x3, CPU2 = 0xF, CPU3 = 0x2;
	return Result;
}

void Resolve(HMODULE hMod)
{
	auto dos  = (PIMAGE_DOS_HEADER)       hMod;
	auto nt   = (PIMAGE_NT_HEADERS)       ((char*)dos + dos->e_lfanew);
	auto pIID = (PIMAGE_IMPORT_DESCRIPTOR)((char*)hMod + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT   ].VirtualAddress);
	auto pIBR = (PIMAGE_BASE_RELOCATION)  ((char*)hMod + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	auto pIED = (PIMAGE_EXPORT_DIRECTORY) ((char*)hMod + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT   ].VirtualAddress);

	DWORD delta = (DWORD)((LPBYTE)hMod - nt->OptionalHeader.ImageBase); // Calculate the delta

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD list = (PWORD)(pIBR + 1);

			for (int i = 0; i < count; i++)
			{
				if (list[i])
				{
					PDWORD ptr = (PDWORD)((LPBYTE)hMod + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	// Resolve DLL imports
	while (pIID->Characteristics)
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)hMod + pIID->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)hMod + pIID->FirstThunk);

		HMODULE hModule = LoadLibraryA((LPCSTR)hMod + pIID->Name);

		if (!hModule)
			return;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				DWORD Function = (DWORD)GetProcAddress(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)hMod + OrigFirstThunk->u1.AddressOfData);
				DWORD Function = (DWORD)GetProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					return;

				FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pIID++;
	}

	uintptr_t* Functions = (uintptr_t*)((LPBYTE)hMod + pIED->AddressOfFunctions);
	uintptr_t* Names     = (uintptr_t*)((LPBYTE)hMod + pIED->AddressOfNames);

	for (int i = 0; i < pIED->NumberOfFunctions; i++)
		Functions[i] += (uintptr_t)hMod;

	for (int i = 0; i < pIED->NumberOfNames; i++)
		Names[i] += (uintptr_t)hMod;
}