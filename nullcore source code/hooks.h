#pragma once
#include <stdint.h>

class CJumpHook
{
public:
	~CJumpHook() { UnHook(); }

	template<class T = void*>
	inline T Location() { return (T)m_loc; }
	template<class T = void*>
	inline T Original() { return (T)m_original; }
	inline bool IsHooked() { return m_hooked; }

	template <class T = void*>
	void Hook(T From, void* To, size_t Length = 0) { Hook((void*)From, To, Length); }
	void Hook(void* From, void* To, size_t Length = 0);
	void Hook(const char* Module, const char* Function, void* To, size_t Length = 0);

	void UnHook();

private:
	bool m_hooked = false;
	void* m_loc = nullptr;
	uint16_t* m_original = nullptr;
	size_t m_hooklen = 0;

	// - Length: 5
	void RelJmp(uintptr_t From, uintptr_t To);

	// - Length: 14
	void AbsJmp(uintptr_t From, uintptr_t To);
};