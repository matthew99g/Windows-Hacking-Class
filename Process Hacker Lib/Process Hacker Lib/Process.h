#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <string.h>


class ProcessHacker
{
public:
	ProcessHacker();
	~ProcessHacker();

	uintptr_t GetProcId(const char *);
	MODULEINFO GetModuleInfo(const char *, uintptr_t, HANDLE);
	bool GetDosHeader(HANDLE, MODULEINFO, PIMAGE_DOS_HEADER);
	bool InfectDosStub(HANDLE, MODULEINFO, PIMAGE_DOS_HEADER, PBYTE, unsigned int);
	bool CreateSignature(MODULEINFO, uintptr_t, unsigned int, HANDLE, BYTE *);
	void SignatureDefaultFormatString(const BYTE *, unsigned int, char *);
	bool CheckSignatureValid(HANDLE, MODULEINFO, PBYTE, DWORD);
	bool CheckSignatureValidString(HANDLE, MODULEINFO, PBYTE, DWORD);
	void AutoBuildSignature(MODULEINFO, uintptr_t, unsigned int, HANDLE, char *, PBYTE);
	uintptr_t GetAddressFromSignatureBytes(HANDLE, MODULEINFO, PBYTE, unsigned int);
	bool WriteTargetOpcode(HANDLE, MODULEINFO, const char *, uintptr_t);

	unsigned int iMaskOpen;
	unsigned int iRecentScanSize;
	unsigned int iAddressOffset;

private:

};
