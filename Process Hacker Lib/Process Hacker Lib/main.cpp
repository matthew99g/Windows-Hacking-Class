#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <stdlib.h>

#include "Process.h"

#define PLAYER_CLASS 0x50f4f4

const char szAppName[] = "ac_client.exe";

int main(const int argc, const char *argv[]) {
	ProcessHacker *Hack = new ProcessHacker;
	unsigned int iStartAddress;
	char *szSignature = new char[256];

	uintptr_t uProcessId = Hack->GetProcId(szAppName);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, uProcessId);
	MODULEINFO modInfo = Hack->GetModuleInfo(szAppName, uProcessId, hProc);

	printf("Enter Start Address 0x");
	scanf("%x", &iStartAddress);
	getchar();

	Hack->AutoBuildSignature(modInfo, uProcessId, iStartAddress, hProc, szSignature);

	delete Hack;
	delete szSignature;

	getchar();

	CloseHandle(hProc);
	return EXIT_SUCCESS;
}