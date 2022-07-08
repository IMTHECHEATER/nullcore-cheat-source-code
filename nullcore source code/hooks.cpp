#include "hooks.h"
#include <Windows.h>

#define Zydis_EXPORTS // Some hacky crap because lazey
#define ZYDIS_DISABLE_FORMATTER
#include <Zydis/Zydis.h>

void CJumpHook::Hook(void* From, void* To, size_t Length)
{
	if (!Length)
	{
		ZydisDecoder de;
#ifdef _WIN64
		ZydisDecoderInit(&de, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#define JMPFUNC AbsJmp
#define JMPSIZE 14
#else
		ZydisDecoderInit(&de, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#define JMPFUNC RelJmp
#define JMPSIZE 5
#endif
		ZyanUSize offset = 0;
		const ZyanUSize length = 0xFF;
		ZydisDecodedInstruction instruction;
		while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
			&de, (char*)From + offset, length - offset, &instruction)))
		{
			offset += instruction.length;
			if (offset >= JMPSIZE)
			{
				Length = offset;
				break;
			}
		}
	}
	DWORD dwOld;
	VirtualProtect((void*)From, Length, PAGE_EXECUTE_READWRITE, &dwOld);

	m_original = (uint16_t*)VirtualAlloc(nullptr, Length + JMPSIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(m_original, (void*)From, Length);

	JMPFUNC((uintptr_t)m_original + Length, (uintptr_t)From + Length);
	JMPFUNC((uintptr_t)From, (uintptr_t)To);

	VirtualProtect((void*)From, Length, dwOld, &dwOld);
	FlushInstructionCache(GetCurrentProcess(), 0, 0);

	m_loc = (void*)From, m_hooklen = Length;
	m_hooked = true;
}

void CJumpHook::Hook(const char* Module, const char* Function, void* To, size_t Length)
{
	HMODULE hMod = 0;
	FARPROC pFunc = 0;
	Hook(pFunc, To, Length);
}

void CJumpHook::UnHook()
{
	if (!m_hooked)
		return;

	DWORD dwOld;
	VirtualProtect(m_loc, m_hooklen, PAGE_EXECUTE_READWRITE, &dwOld);
	memcpy_s(m_loc, m_hooklen, m_original, m_hooklen);
	VirtualProtect(m_loc, m_hooklen, dwOld, &dwOld);
	VirtualFree(m_original, 0, MEM_RELEASE);
	FlushInstructionCache(GetCurrentProcess(), 0, 0);

	m_loc = nullptr, m_hooklen = 0;
	m_hooked = false;
}

void CJumpHook::RelJmp(UINT_PTR From, UINT_PTR To)
{
	*(BYTE*)From = 0xE9;
	*(DWORD*)(From + 1) = To - From - 5;
}

void CJumpHook::AbsJmp(UINT_PTR From, UINT_PTR To)
{
	PBYTE b = (PBYTE)From;

	*(WORD*)From = MAKEWORD(0xFF, 0x25);	// jmp [rip+imm32]
	*(DWORD*)&b[2] = 0;						// rip + 0
	*(UINT_PTR*)&b[6] = To;
}