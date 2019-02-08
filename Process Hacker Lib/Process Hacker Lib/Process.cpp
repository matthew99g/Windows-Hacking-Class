#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <stdlib.h>

#include "Process.h"

ProcessHacker::ProcessHacker()
{
	iMaskOpen = 0;
}

ProcessHacker::~ProcessHacker()
{
}

uintptr_t ProcessHacker::GetProcId(const char *szProcessName) {
	uintptr_t uProcessId = NULL;
	PROCESSENTRY32 pEntry = { sizeof(pEntry) };
	HANDLE hProcessList = NULL;

	do {

		hProcessList = CreateToolhelp32Snapshot(PROCESS_ALL_ACCESS, 0);
		if (hProcessList == INVALID_HANDLE_VALUE)
			return uProcessId;

		if (Process32First(hProcessList, &pEntry)) {
			do {

				if (!strcmp(pEntry.szExeFile, szProcessName)) {
					uProcessId = pEntry.th32ProcessID;
					break;
				}

			} while (Process32Next(hProcessList, &pEntry));
		}

	} while (!uProcessId);


#ifdef _DEBUG
	printf("[DEBUG] Process ID: %d\n", uProcessId);
#endif // _DEBUG

	return uProcessId;
}

MODULEINFO ProcessHacker::GetModuleInfo(const char *szModuleName, uintptr_t uProcessId, HANDLE hProc) {
	MODULEINFO modInfo = { 0 };
	MODULEENTRY32 mEntry = { sizeof(mEntry) };
	HANDLE hModuleList = NULL;

	do {
		hModuleList = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
			uProcessId);
		if (hModuleList == INVALID_HANDLE_VALUE)
			return modInfo;

		if (Module32First(hModuleList, &mEntry)) {

			do {

				if (!strcmp(mEntry.szModule, szModuleName)) {
					GetModuleInformation(hProc, mEntry.hModule, &modInfo, sizeof(modInfo));
					break;
				}

			} while (Module32Next(hModuleList, &mEntry));

		}

	} while (!modInfo.lpBaseOfDll);

#ifdef _DEBUG
	printf("[DEBUG] Base Of Module: 0x%X\n", modInfo.lpBaseOfDll);
#endif // _DEBUG

	return modInfo;
}

bool ProcessHacker::GetDosHeader(HANDLE hProc, MODULEINFO modInfo, PIMAGE_DOS_HEADER pIDH) {
	uintptr_t iModuleBase = (uintptr_t)modInfo.lpBaseOfDll;

	DWORD dwOld = NULL;
	DWORD dwBytesRead = NULL;

	VirtualProtectEx(hProc, (LPVOID)iModuleBase, sizeof(IMAGE_DOS_HEADER), PAGE_EXECUTE_READWRITE, &dwOld);

	ReadProcessMemory(hProc, (LPCVOID)iModuleBase, pIDH, sizeof(IMAGE_DOS_HEADER), &dwBytesRead);

	VirtualProtectEx(hProc, (LPVOID)iModuleBase, sizeof(IMAGE_DOS_HEADER), dwOld, NULL);

	if (dwBytesRead < sizeof(IMAGE_DOS_HEADER) || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

#ifdef _DEBUG
	printf("[DEBUG] e_lfanew: 0x%x\n", pIDH->e_lfanew);
	printf("[DEBUG] MZ: 0x%x\n", pIDH->e_magic);
#endif // _DEBUG

	return true;
}

bool ProcessHacker::InfectDosStub(HANDLE hProc, MODULEINFO modInfo, PIMAGE_DOS_HEADER pIDH,
	PBYTE pShellCode, unsigned int iLength) {
	uintptr_t uDosStubBase = (uintptr_t)modInfo.lpBaseOfDll + pIDH->e_lfarlc - 1;

	DWORD dwOld = NULL;
	VirtualProtectEx(hProc, (LPVOID)uDosStubBase, sizeof(IMAGE_DOS_HEADER), PAGE_EXECUTE_READWRITE, &dwOld);

	WriteProcessMemory(hProc, (LPVOID)uDosStubBase, pShellCode, iLength, NULL);

#ifdef _DEBUG
	DWORD dwBytesRead = NULL;

	BYTE temp[256];
	ReadProcessMemory(hProc, (LPCVOID)uDosStubBase, temp, 64, &dwBytesRead);

	printf("\n");

	for (int i = 0; i < 64; i++) {
		printf("%x", temp[i]);
		if (i % 16 == 0 && i != 0)
			printf("\n");
	}

	printf("\n");
#endif // _DEBUG

	VirtualProtectEx(hProc, (LPVOID)uDosStubBase, sizeof(IMAGE_DOS_HEADER), dwOld, NULL);

	return true;
}

bool ProcessHacker::CreateSignature(MODULEINFO modInfo, uintptr_t uStartAddress,
	unsigned int iSizeOfScan, HANDLE hProc, BYTE *szPtr) {
	// Declare Base and Size of Memory
	uintptr_t uMemoryBase;
	uintptr_t uMemorySize;

	// Declare Offset Variable
	unsigned int iOffset;

	// Define Memory Base and Size
	uMemoryBase = (uintptr_t)modInfo.lpBaseOfDll;
	uMemorySize = (uintptr_t)modInfo.SizeOfImage;

	// Define Offset: Offset = Starting addres - Base of Memory
	iOffset = uStartAddress - uMemoryBase;

	// Clear Memory Protection Scheme
	DWORD dwOld = NULL;
	VirtualProtectEx(hProc, (LPVOID)(uMemoryBase + iOffset), iSizeOfScan,
		PAGE_EXECUTE_READWRITE, &dwOld);

	// Read Memory into a char *
	SIZE_T iBytesRead = 0;
	ReadProcessMemory(hProc, (LPCVOID)(uMemoryBase + iOffset), szPtr, iSizeOfScan,
		(SIZE_T *)(&iBytesRead));

	// Write old Memory Permission Scheme
	VirtualProtectEx(hProc, (LPVOID)(uMemoryBase + iOffset), iSizeOfScan,
		dwOld, NULL);

	if (iBytesRead < iSizeOfScan)
		return false;

	return true;
}

void ProcessHacker::SignatureDefaultFormatString(const BYTE *szSignatureData, unsigned int iMemoryLength,
	char *szSignature) {
	char szBuffer[5];
	int maskCount = 0;
	int mvCount = 0;

	ZeroMemory(szSignature, iMemoryLength);

	for (int index = 0; index < iMemoryLength; index++) {
		sprintf(szBuffer, "\\x%02x", szSignatureData[index]);
		strcat(szSignature, szBuffer);

		if (szSignatureData[index] == 0xe8 && index < iMemoryLength) {
			for (int i = 0; i < 4 && index < iMemoryLength; i++) {
				index++;
				strcat(szSignature, "?");
				maskCount++;
				iMaskOpen++;
			}
		}
		if (szSignatureData[index] == 0x89 && index < iMemoryLength) {
			index++;
			mvCount++;

			sprintf(szBuffer, "\\x%02x", szSignatureData[index]);
			strcat(szSignature, szBuffer);

			for (int i = 0; i < 4 && index < iMemoryLength; i++) {
				index++;
				strcat(szSignature, "?");
				maskCount++;
				iMaskOpen++;
			}
		}
	}
	szSignature[4 * iMemoryLength - (maskCount * 3) + (mvCount * 3) + 3] = 0;
}

bool ProcessHacker::CheckSignatureValid(HANDLE hProcess, MODULEINFO modInfo, PBYTE szBytes, DWORD dwSignatureSizeTemp) {
	DWORD dwOld = 0;
	DWORD count = 0;

	DWORD dwMemoryBase = (DWORD)modInfo.lpBaseOfDll;
	DWORD dwMemorySize = (DWORD)modInfo.SizeOfImage;

	bool bSearch = false;

	DWORD dwSignatureSize;

	if (iMaskOpen != 0)
		dwSignatureSize = dwSignatureSizeTemp - ((iMaskOpen) * 4);
	else
		dwSignatureSize = dwSignatureSizeTemp;

	BYTE *buf = new BYTE[dwMemorySize];
	ZeroMemory(buf, sizeof(buf));

	VirtualProtectEx(hProcess, (LPVOID)(dwMemoryBase), dwMemorySize, PROCESS_ALL_ACCESS, &dwOld);
	ReadProcessMemory(hProcess, (LPCVOID)(dwMemoryBase), buf, dwMemorySize, NULL);

	int p = 0;
	DWORD i = 0;

	for (p = 0; p < dwMemorySize - dwSignatureSize; p++) {
		for (i = 0; i < dwSignatureSize; i++) {
			bSearch = (*((BYTE *)(buf + i + p)) == *((BYTE *)(szBytes + i)) || *((BYTE *)(szBytes + i)) == '?') ? true : false;
			if (!bSearch)
				break;
		}

		if (bSearch) {
			count++;
			printf("%d @ 0x%X\n", count, (DWORD)(DWORD *)(p + dwMemoryBase));
		}

	}

	VirtualProtectEx(hProcess, (LPVOID)(dwMemoryBase), dwMemorySize, dwOld, NULL);

	if (count != 1) {
		delete buf;
		iMaskOpen = 0;
		return false;
	}

	printf("Found %d times\n", count);
	delete buf;
	iMaskOpen = 0;
	return true;
}

bool ProcessHacker::CheckSignatureValidString(HANDLE hProcess, MODULEINFO modInfo, PBYTE szBytes, DWORD dwSignatureSizeTemp) {
	DWORD dwOld = 0;
	DWORD count = 0;

	DWORD dwMemoryBase = (DWORD)modInfo.lpBaseOfDll;
	DWORD dwMemorySize = (DWORD)modInfo.SizeOfImage;

	DWORD dwSignatureSize = (DWORD)strlen((const char *)szBytes);

	bool bSearch = false;

	BYTE *buf = new BYTE[dwMemorySize];
	ZeroMemory(buf, sizeof(buf));

	VirtualProtectEx(hProcess, (LPVOID)(dwMemoryBase), dwMemorySize, PROCESS_ALL_ACCESS, &dwOld);
	ReadProcessMemory(hProcess, (LPCVOID)(dwMemoryBase), buf, dwMemorySize, NULL);

	int p = 0;
	DWORD i = 0;

	for (p = 0; p < dwMemorySize - dwSignatureSize; p++) {
		for (i = 0; i < dwSignatureSize; i++) {
			bSearch = (*((BYTE *)(buf + i + p)) == *((BYTE *)(szBytes + i)) || *((BYTE *)(szBytes + i)) == '?') ? true : false;
			if (!bSearch)
				break;
		}

		if (bSearch) {
			count++;
			printf("%d @ 0x%X\n", count, (DWORD)(DWORD *)(p + dwMemoryBase));
		}

	}

	VirtualProtectEx(hProcess, (LPVOID)(dwMemoryBase), dwMemorySize, dwOld, NULL);

	if (count != 1)
		return false;

	printf("Found %d times\n", count);
	delete buf;
	return true;
}

void ProcessHacker::AutoBuildSignature(MODULEINFO modInfo, uintptr_t uProcessId, unsigned int iStartAddress, HANDLE hProc, char *szSavedSignature) {
	unsigned int iSignatureLength = 2;
	unsigned int iStartAddressTemp = iStartAddress;

	BYTE *szSignature = 0;

	char *szSignatureString = 0;

	while (true) {
		szSignature = new BYTE[iSignatureLength * 4];
		szSignatureString = new char[iSignatureLength * 6];

		if (!CreateSignature(modInfo, (uintptr_t)iStartAddress, iSignatureLength,
			hProc, szSignature)) {
			fprintf(stderr, "Failed to Generate Signature!\n");
			getchar();
			ExitProcess(EXIT_FAILURE);
		}

		SignatureDefaultFormatString((const BYTE *)szSignature, iSignatureLength, szSignatureString);

		if (CheckSignatureValid(hProc, modInfo, (PBYTE)szSignature, iSignatureLength)) {
			break;
		}
		else {
			iSignatureLength++;
			if (iSignatureLength > 24) {
				iSignatureLength = 2;
				iStartAddress -= 1;
			}
		}

		delete szSignatureString;
		delete szSignature;
	}

#ifdef _DEBUG
	printf("\nGenerated Signature @ 0x%x | 0x%x Bytes from 0x%x\nSignature: %s\n",
		iStartAddress, iStartAddressTemp - iStartAddress, iStartAddressTemp, szSignatureString);
#endif // _DEBUG


	strcpy(szSavedSignature, szSavedSignature);

	delete szSignatureString;
	delete szSignature;

}