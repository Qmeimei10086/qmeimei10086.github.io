---
layout:     post
title:      win内核初探2-无Loadlibrary的DLL注射器样本
date:       2026-4-5
author:     Qmeimei10086
header-style: text
tags:
    - 反射注入
---

# 前言
作为学习windows内核机制的记录，顺便水一篇博客嘻嘻  
参考https://www.bilibili.com/video/BV1qK6QBrEqH  
# 代码  
injector.h  
```c
#pragma once
#include <Windows.h>
#include <iostream>
#include <winnt.h>
#include <TlHelp32.h>
#include <psapi.h>



typedef struct DllMainParams {
	LPVOID hModule;
	DWORD dwReason;
	LPVOID lpReserved;
} DllMainParams, * PDllMainParams;

using namespace std;
LPVOID ReadPEFile(const char* filePath, DWORD* pFileSize);
LPVOID BuildMemoryImage(LPVOID pFileBase, DWORD* pImageSize);
BOOL ProcessRelocation(LPVOID pMemoryImage, LPVOID pRemoteBase);
HMODULE GetRemoteModuleHandle(DWORD dwProcessld, const char* moduleName);
BOOL FixImportTable(LPVOID pMemoryImage, LPVOID pRemoteBase,DWORD dwProcessld);
BOOL SetSectionProtections(HANDLE hProcess, LPVOID pRemoteBase, LPVOID pMemoryImage);
BOOL InjectDllWithManualMapping(DWORD dwProcessId, const char* dllPath);
```  
injector.cpp  
```c
#include "injector.h"

static const char* ResolveImportModuleName(const char* importModuleName) {
	if (!importModuleName) {
		return importModuleName;
	}

	if (_strnicmp(importModuleName, "api-ms-win-crt-", 15) == 0) {
		return "ucrtbase.dll";
	}

	return importModuleName;
}

LPVOID ReadPEFile(const char* filePath, DWORD* pFileSize) {
	HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE) {
		cout << "Failed to open file: " << filePath << endl;
		return NULL;

	}

	DWORD fileSize = GetFileSize(hFile, NULL);
	if(fileSize == INVALID_FILE_SIZE || fileSize < sizeof(IMAGE_DOS_HEADER)) {
		cout << "Failed to get file size: " << filePath << endl;
		CloseHandle(hFile);
		return NULL;
	}

	LPVOID fileBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(fileBuffer == NULL) {
		cout << "Failed to allocate memory for file: " << filePath << endl;
		CloseHandle(hFile);
		return NULL;
	}
	DWORD bytesRead = 0;
	if(!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
		cout << "Failed to read file: " << filePath << endl;
		VirtualFree(fileBuffer, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return NULL;
	}
	CloseHandle(hFile);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "Invalid Dos signature: " << filePath << endl;
		VirtualFree(fileBuffer, 0, MEM_RELEASE);
		return NULL;
	}

	if(pDosHeader->e_lfanew > fileSize - sizeof(IMAGE_NT_HEADERS)) {
		cout << "Invalid PE header offect: " << filePath << endl;
		VirtualFree(fileBuffer, 0, MEM_RELEASE);
		return NULL;
	}

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileBuffer + pDosHeader->e_lfanew);
	if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		cout << "Invalid PE signature: " << filePath << endl;
		VirtualFree(fileBuffer, 0, MEM_RELEASE);
		return NULL;
	}

	if(pFileSize) {
		*pFileSize = fileSize;
	}
	return fileBuffer;
}

LPVOID BuildMemoryImage(LPVOID pFileBase, DWORD* pImageSize) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pFileBase + pDosHeader->e_lfanew);

	DWORD imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
	LPVOID pMemoryImage = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if(!pMemoryImage) {
		cout << "Failed to allocate memory for image" << endl;
		return NULL;
	}

	memset(pMemoryImage, 0, imageSize);
	memcpy(pMemoryImage, pFileBase, pNtHeaders->OptionalHeader.SizeOfHeaders);
	cout << "Copy PE headers: " << dec << pNtHeaders->OptionalHeader.SizeOfHeaders << " bytes" << endl;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	for(int i=0; i<pNtHeaders->FileHeader.NumberOfSections; i++) {
		LPVOID pDest = (BYTE*)pMemoryImage + pSectionHeader[i].VirtualAddress;
		LPVOID pSrc = (BYTE*)pFileBase + pSectionHeader[i].PointerToRawData;
		DWORD size = min(pSectionHeader[i].SizeOfRawData, pSectionHeader[i].Misc.VirtualSize);
		
		if (pSectionHeader[i].Misc.VirtualSize > size) {
			DWORD bssSize = pSectionHeader[i].Misc.VirtualSize - size;
			memset((BYTE*)pDest + size, 0, bssSize);
		}
		
		memcpy(pDest, pSrc, size);
		cout << "Copy section " << string((char*)pSectionHeader[i].Name) << ": " << dec << size << " bytes" << endl;
	}

	if (pImageSize) {
		*pImageSize = imageSize;
	}
	return pMemoryImage;
}

BOOL ProcessRelocation(LPVOID pMemoryImage, LPVOID pRemoteBase) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMemoryImage;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pMemoryImage + pDosHeader->e_lfanew);

	ULONGLONG originalBase = pNtHeaders->OptionalHeader.ImageBase;
	ULONGLONG newBase = (ULONGLONG)pRemoteBase;
	LONGLONG delta = newBase - originalBase;

	if (delta == 0) {
		cout << "No relocation needed" << endl;
		return TRUE;
	}

	DWORD relocRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD relocSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if(relocRVA == 0 || relocSize == 0) {
		cout << "No relocation info found,ignoring..." << endl;
		return FALSE;
	}

	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pMemoryImage + relocRVA);
	int relocCount = 0;
	int relocEntryCount = 0;

	while(pReloc->VirtualAddress && (BYTE*)pReloc < (BYTE*)pMemoryImage + relocRVA + relocSize) {
		DWORD numEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD pRelocEntries = (PWORD)((BYTE*)pReloc + sizeof(IMAGE_BASE_RELOCATION));
		
		for (DWORD i = 0; i < numEntries; i++) {
			WORD relocType = pRelocEntries[i] >> 12;
			WORD offset = pRelocEntries[i] & 0x0FFF;

			if (relocType == IMAGE_REL_BASED_DIR64) {
				ULONGLONG* pPatchAddr = (ULONGLONG*)((BYTE*)pMemoryImage + pReloc->VirtualAddress + offset);
				*pPatchAddr += delta;
				relocEntryCount++;
			}
			else if (relocType == IMAGE_REL_BASED_HIGHLOW) {
				cout << "Found 32-bit relocation in x64-only injector path" << endl;
				return FALSE;
			}


		}
		relocCount++;
		pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);

	}

	cout << "Processed " << relocCount << " relocation blocks, " << relocEntryCount << " entries patched." << endl;
	return TRUE;
}

HMODULE GetRemoteModuleHandle(DWORD dwProcessld, const char* moduleName) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcessld);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		cout << "Failed to create snapshot for process: " << dwProcessld << endl;
		return NULL;
	}
	WCHAR wModuleName[MAX_PATH];
	if (MultiByteToWideChar(CP_ACP, 0, moduleName, -1, wModuleName, MAX_PATH) == 0) {
		CloseHandle(hSnapshot);
		return NULL;
	}

	MODULEENTRY32W me32;
	me32.dwSize = sizeof(MODULEENTRY32W);
	if(Module32FirstW(hSnapshot, &me32)) {
		do {
			if (lstrcmpiW(me32.szModule, wModuleName) == 0 || lstrcmpiW(me32.szExePath, wModuleName) == 0) {
				CloseHandle(hSnapshot);
				return me32.hModule;
			}
		} while (Module32NextW(hSnapshot, &me32));
	}
	CloseHandle(hSnapshot);
	return NULL;
}

BOOL FixImportTable(LPVOID pMemoryImage, LPVOID pRemoteBase, DWORD dwProcessld) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMemoryImage;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pMemoryImage + pDosHeader->e_lfanew);

	DWORD importRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if(importRVA == 0) {
		cout << "No import table found, ignoring..." << endl;
		return TRUE;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pMemoryImage + importRVA);
	while (pImportDesc->Name) {
		char* dllName = (char*)((BYTE*)pMemoryImage + pImportDesc->Name);
		const char* resolvedDllName = ResolveImportModuleName(dllName);
		if (_stricmp(dllName, resolvedDllName) != 0) {
			cout << "Fixing imports from: " << dllName << " (mapped to " << resolvedDllName << ")" << endl;
		}
		else {
			cout << "Fixing imports from: " << dllName << endl;
		}

		HMODULE hLocalModule = LoadLibraryA(resolvedDllName);
		if(!hLocalModule) {
			cout << "Failed to load local module: " << resolvedDllName << endl;
			return FALSE;
		}

		PIMAGE_THUNK_DATA pOrigFirstThunk = pImportDesc->OriginalFirstThunk
			? (PIMAGE_THUNK_DATA)((BYTE*)pMemoryImage + pImportDesc->OriginalFirstThunk)
			: (PIMAGE_THUNK_DATA)((BYTE*)pMemoryImage + pImportDesc->FirstThunk);
		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)pMemoryImage + pImportDesc->FirstThunk);

		int funcCount = 0;
		while (pOrigFirstThunk->u1.AddressOfData) {
			LPVOID pLocalFunc = NULL;
			char funcName[256] = { 0 };

			if (IMAGE_SNAP_BY_ORDINAL64(pOrigFirstThunk->u1.Ordinal)) {
				// Import by ordinal
				WORD ordinal = (WORD)IMAGE_ORDINAL64(pOrigFirstThunk->u1.Ordinal);
				pLocalFunc = GetProcAddress(hLocalModule, (LPCSTR)ordinal);
				sprintf_s(funcName, "Index:%d", ordinal);

			}
			else {
				// Import by name
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pMemoryImage + pOrigFirstThunk->u1.AddressOfData);
				pLocalFunc = GetProcAddress(hLocalModule, pImportByName->Name);
				strcpy_s(funcName, pImportByName->Name);
			}
			if (pLocalFunc) {
				ULONGLONG remoteFuncAddr = 0;
				HMODULE hRemoteModule = GetRemoteModuleHandle(dwProcessld, resolvedDllName);
				if(!hRemoteModule) {
					cout << "Target process does not have required module loaded: " << resolvedDllName << endl;
					FreeLibrary(hLocalModule);
					return FALSE;
				}

				MODULEINFO ModuleInfo = { 0 };
				if (K32GetModuleInformation(GetCurrentProcess(), hLocalModule, &ModuleInfo, sizeof(ModuleInfo))) {
					ULONGLONG localModuleEnd = (ULONGLONG)ModuleInfo.lpBaseOfDll + ModuleInfo.SizeOfImage;
					if ((ULONGLONG)pLocalFunc < (ULONGLONG)hLocalModule || (ULONGLONG)pLocalFunc >= localModuleEnd) {
						HMODULE hOwnerLocal = NULL;
						if (!GetModuleHandleExA(
							GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
							GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
							(LPCSTR)pLocalFunc,
							&hOwnerLocal
						) || !hOwnerLocal) {
							cout << "Failed to resolve forwarded import owner module: " << funcName << endl;
							FreeLibrary(hLocalModule);
							return FALSE;
						}

						char ownerPath[MAX_PATH] = { 0 };
						if (!GetModuleFileNameA(hOwnerLocal, ownerPath, MAX_PATH)) {
							cout << "Failed to resolve forwarded import owner module path: " << funcName << endl;
							FreeLibrary(hLocalModule);
							return FALSE;
						}

						char* ownerModuleName = strrchr(ownerPath, '\\');
						ownerModuleName = ownerModuleName ? ownerModuleName + 1 : ownerPath;

						HMODULE hOwnerRemote = GetRemoteModuleHandle(dwProcessld, ownerModuleName);
						if (!hOwnerRemote) {
							cout << "Target process does not have forwarded import owner module loaded: " << ownerModuleName << endl;
							FreeLibrary(hLocalModule);
							return FALSE;
						}

						ULONGLONG forwardedOffset = (ULONGLONG)pLocalFunc - (ULONGLONG)hOwnerLocal;
						remoteFuncAddr = (ULONGLONG)hOwnerRemote + forwardedOffset;
					}
					else {
						ULONGLONG offset = (ULONGLONG)pLocalFunc - (ULONGLONG)hLocalModule;
						remoteFuncAddr = (ULONGLONG)hRemoteModule + offset;
					}
				}
				else {
					ULONGLONG offset = (ULONGLONG)pLocalFunc - (ULONGLONG)hLocalModule;
					remoteFuncAddr = (ULONGLONG)hRemoteModule + offset;
				}
				pThunk->u1.Function = remoteFuncAddr;

			
			}
			
			
			else {
				FreeLibrary(hLocalModule);
				return FALSE;
			}
			funcCount++;
			pOrigFirstThunk++;
			pThunk++;

		}
		cout << "Fixed " << funcCount << " imports from " << dllName << endl;
		FreeLibrary(hLocalModule);
		pImportDesc++;
	}
	return TRUE;
}

BOOL SetSectionProtections(HANDLE hProcess, LPVOID pRemoteBase, LPVOID pMemoryImage) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMemoryImage;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pMemoryImage + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	BOOL allSectionsProtected = TRUE;

	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		DWORD protect = PAGE_READONLY;
		if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			protect = (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
		}
		else if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
			protect = PAGE_READWRITE;
		}

		LPVOID pSectionAddr = (BYTE*)pRemoteBase + pSectionHeader[i].VirtualAddress;
		DWORD oldProtect = 0;
		if (!VirtualProtectEx(hProcess, pSectionAddr, pSectionHeader[i].Misc.VirtualSize, protect, &oldProtect)) {
			cout << "Failed to set protection for section " << string((char*)pSectionHeader[i].Name) << endl;
			allSectionsProtected = FALSE;

		}
		else {
			cout << "Set protection for section " << string((char*)pSectionHeader[i].Name) << " to " << ((protect == PAGE_EXECUTE_READWRITE) ? "PAGE_EXECUTE_READWRITE" : (protect == PAGE_EXECUTE_READ) ? "PAGE_EXECUTE_READ" : (protect == PAGE_READWRITE) ? "PAGE_READWRITE" : "PAGE_READONLY") << endl;
		}
	}

	return allSectionsProtected;
}

BOOL InjectDllWithManualMapping(DWORD dwProcessId, const char* dllPath) {
	cout << "Starting manual mapping injection..." << endl;
	HANDLE hProcess = OpenProcess(
		PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_READ |
		PROCESS_VM_WRITE |
		PROCESS_SUSPEND_RESUME,
		FALSE,
		dwProcessId
	);
	if (!hProcess) {
		cout << "Failed to open target process: " << dwProcessId << endl;
		return FALSE;
	}

	cout << "successfully opened target process: " << dwProcessId << endl;
	DWORD fileSize = 0;
	LPVOID pFileBase = ReadPEFile(dllPath, &fileSize);
	if(!pFileBase) {
		std::cout << "Failed to read PE file: " << dllPath << std::endl;
		CloseHandle(hProcess);
		return FALSE;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pFileBase + pDosHeader->e_lfanew);

	cout << "PE file read successfully: " << dllPath << endl;
	cout << "Image Base: 0x" << hex << pNtHeaders->OptionalHeader.ImageBase << endl;
	cout << "Image Size: " << dec << pNtHeaders->OptionalHeader.SizeOfImage << " bytes" << endl;
	cout << "Number of sections: " << pNtHeaders->FileHeader.NumberOfSections << endl;

	BOOL isWow64 = FALSE;
	if (!IsWow64Process(hProcess, &isWow64)) {
		cout << "Failed to query target process architecture" << endl;
		VirtualFree(pFileBase, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || isWow64) {
		cout << "This injector path currently supports x64 DLL into x64 target process only" << endl;
		VirtualFree(pFileBase, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	cout << "Building memory image..." << endl;
	DWORD imageSize = 0;
	LPVOID pMemoryImage = BuildMemoryImage(pFileBase, &imageSize);
	if(!pMemoryImage) {
		cout << "Failed to build memory image" << endl;
		VirtualFree(pFileBase, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}
	cout << "Successfully built memory image. Size: " << dec << imageSize << " bytes" << endl;
	
	cout << "Allocating memory for image in target process..." << endl;
	LPVOID pRemoteImage = VirtualAllocEx(hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(!pRemoteImage) {
		cout << "Failed to allocate memory in target process" << endl;
		VirtualFree(pMemoryImage, 0, MEM_RELEASE);
		VirtualFree(pFileBase, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}
	cout << "Memory allocated in target process at: 0x" << hex << pRemoteImage << endl;
	
	
	
	cout << "Fixing import address table" << endl;
	if(!FixImportTable(pMemoryImage, pRemoteImage, dwProcessId)) {
		cout << "Failed to fix import table" << endl;
		VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
		VirtualFree(pMemoryImage, 0, MEM_RELEASE);
		VirtualFree(pFileBase, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}
	cout << "Import table fixed successfully" << endl;

	cout << "Processing relocations..." << endl;
	if(!ProcessRelocation(pMemoryImage, pRemoteImage)) {
		cout << "Failed to process relocations" << endl;
		VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
		VirtualFree(pMemoryImage, 0, MEM_RELEASE);
		VirtualFree(pFileBase, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}
	cout << "Relocations processed successfully" << endl;



	cout << "Writeing memory image to target process..." << endl;
	if (!(WriteProcessMemory(hProcess, pRemoteImage, pMemoryImage, imageSize, NULL))) {
		cout << "Failed to write memory to target process" << endl;
		VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
		VirtualFree(pMemoryImage, 0, MEM_RELEASE);
		VirtualFree(pFileBase, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}
	FlushInstructionCache(hProcess, pRemoteImage, imageSize);
	cout << "Memory image written to target process successfully" << endl;
	
	cout << "Setting section permissions..." << endl;
	if (!SetSectionProtections(hProcess, pRemoteImage, pMemoryImage)) {
		cout << "Failed to set section protections" << endl;
	}
	else {
		cout << "Section protections set successfully" << endl;
	}

	pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pMemoryImage + pDosHeader->e_lfanew);
	DWORD entryPointRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	LPVOID pRemoteEntryPoint = (BYTE*)pRemoteImage + entryPointRVA;

	BYTE stubTemplate[] = {
		0x48,0x83,0xEC,0x28,				// sub rsp, 28h
		0x48,0x89,0x44,0x24,0x20,			// mov [rsp+20h], rax
		0x48,0x89,0x4C,0x24,0x18,			// mov [rsp+18h], rcx
		0x48,0x89,0x54,0x24,0x10,			// mov [rsp+10h], rdx
		0x4C,0x89,0x44,0x24,0x08,			// mov [rsp+8], r8

		0x49,0xBA,0,0,0,0,0,0,0,0,			// mov r10, <params>
		0x49,0x8B,0x0A,						// mov rcx, [r10]
		0x41,0x8B,0x52,0x08,				// mov edx, [r10+8]
		0x4D,0x8B,0x42,0x10,				// mov r8, [r10+16]

		0x48,0xB8,0,0,0,0,0,0,0,0,			// mov rax, <DllMain>
		0xFF,0xD0,							// call rax

		0x4C,0x8B,0x44,0x24,0x08,			// mov r8, [rsp+8]
		0x48,0x8B,0x54,0x24,0x10,			// mov rdx, [rsp+10h]
		0x48,0x8B,0x4C,0x24,0x18,			// mov rcx, [rsp+18h]
		0x48,0x8B,0x44,0x24,0x20,			// mov rax, [rsp+20h]
		0x48,0x83,0xC4,0x28,				// add rsp, 28h

		0x49,0xBB,0,0,0,0,0,0,0,0,			// mov r11, <originalRIP>
		0x41,0xFF,0xE3						// jmp r11
	};

	LPVOID pRemoteStub = VirtualAllocEx(hProcess, NULL, sizeof(stubTemplate), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pRemoteStub) {
		cout << "Failed to allocate memory for remote stub" << endl;
		VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
		VirtualFree(pMemoryImage, 0, MEM_RELEASE);
		VirtualFree(pFileBase, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}
	cout << "Memory allocated for remote stub at: 0x" << hex << pRemoteStub << endl;

	cout << "Preparing remote stub..." << endl;
	
	DllMainParams params;
	params.hModule = pRemoteImage;
	params.dwReason = DLL_PROCESS_ATTACH;
	params.lpReserved = NULL;
	LPVOID pRemoteParams = VirtualAllocEx(hProcess, NULL, sizeof(DllMainParams), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!pRemoteParams || !WriteProcessMemory(hProcess, pRemoteParams, &params, sizeof(DllMainParams), NULL)) {
		cout << "Failed to allocate/write memory for DLL main parameters" << endl;
		if (pRemoteParams) {
			VirtualFreeEx(hProcess, pRemoteParams, 0, MEM_RELEASE);
		}
		VirtualFreeEx(hProcess, pRemoteStub, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
		VirtualFree(pMemoryImage, 0, MEM_RELEASE);
		VirtualFree(pFileBase, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if(hSnapshot == INVALID_HANDLE_VALUE) {
		cout << "Failed to create thread snapshot" << endl;
		VirtualFreeEx(hProcess, pRemoteParams, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pRemoteStub, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
		VirtualFree(pMemoryImage, 0, MEM_RELEASE);
		VirtualFree(pFileBase, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	int hijackCount = 0;
	if(Thread32First(hSnapshot, &te32)) {
		do {
			if (te32.th32OwnerProcessID == dwProcessId) {
				HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,FALSE,te32.th32ThreadID);
				if (hThread) {
					if (SuspendThread(hThread) == (DWORD)-1) {
						cout << "Failed to suspend thread: " << te32.th32ThreadID << endl;
						CloseHandle(hThread);
						continue;
					}
					CONTEXT ctx;
					ctx.ContextFlags = CONTEXT_FULL;
					if (!GetThreadContext(hThread, &ctx)) {
						cout << "Failed to get context of thread: " << te32.th32ThreadID << endl;
						ResumeThread(hThread);
						CloseHandle(hThread);
						continue;
					}
					ULONGLONG originalRip = ctx.Rip;
					BYTE stub[sizeof(stubTemplate)];
					memcpy(stub, stubTemplate, sizeof(stubTemplate));
					*(ULONGLONG*)(stub + 26) = (ULONGLONG)pRemoteParams;
					*(ULONGLONG*)(stub + 47) = (ULONGLONG)pRemoteEntryPoint;
					*(ULONGLONG*)(stub + 83) = originalRip;
					if(!WriteProcessMemory(hProcess, pRemoteStub, stub, sizeof(stub), NULL)) {
						cout << "Failed to write remote stub to thread: " << te32.th32ThreadID << endl;
						ResumeThread(hThread);
						CloseHandle(hThread);
						continue;
					}
					FlushInstructionCache(hProcess, pRemoteStub, sizeof(stub));
					ctx.Rip = (ULONGLONG)pRemoteStub;
					if (!SetThreadContext(hThread, &ctx)) {
						cout << "Failed to set context of thread: " << te32.th32ThreadID << endl;
						ResumeThread(hThread);
						CloseHandle(hThread);
						continue;
					}
					if(ResumeThread(hThread) == (DWORD)-1) {
						cout << "Failed to resume thread: " << te32.th32ThreadID << endl;
						CloseHandle(hThread);
						continue;
					}
					cout << "Successed to hijacked thread " << te32.th32ThreadID << " to execute injected DLL" << endl;
					CloseHandle(hThread);
					hijackCount = 1;
					break;
				}
			}
		} while (Thread32Next(hSnapshot, &te32));
	}
	CloseHandle(hSnapshot);
	if (hijackCount > 0) {
		cout << "Successfully hijacked " << hijackCount << " threads to execute the injected DLL" << endl;
	}
	else {
		cout << "Failed to hijack any threads" << endl;

	}

	cout << "DLL manual mapping injection completed" << endl;
	// Keep remote stub/params allocated to avoid racing with hijacked thread execution.
	VirtualFree(pMemoryImage, 0, MEM_RELEASE);
	VirtualFree(pFileBase, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return TRUE;
}
```
Injectormain.cpp  
```c
#include "injector.h"
#include <limits>
#include <string>

int main() {
	DWORD targetProcessId;
	cout << "Enter target process ID: ";
	cin >> targetProcessId;
	cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
	
	std::string dllPath;
	cout << "Enter path to DLL to inject: ";
	std::getline(cin, dllPath);
	if (dllPath.empty()) {
		cout << "DLL path is empty" << endl;
		return 1;
	}

	InjectDllWithManualMapping(targetProcessId, dllPath.c_str());
		
}
```
# dll机制
多水一点，加一点ai的回答嘻嘻   
DLL共享策略  
```text

DLL 文件不会为每个进程都完整拷贝一份到物理内存。
代码页（.text）和只读页通常可以跨进程共享同一份物理页。
可写页（.data）通常是每个进程私有，不共享。
底层原理（Windows）可以理解成这几步：

LoadLibrary 不是简单 ReadFile+memcpy，而是让内核创建/复用一个“映像节对象”（section object）。
进程拿到的是各自的“虚拟地址映射”（VAD），不是独占文件副本。
多个进程把同一个 DLL 的同一批文件页映射到自己的虚拟地址空间里。
只读页可以直接共享同一物理页，所以看起来“只加载一份”。
可写页采用 Copy-on-Write：一开始可指向同页，但一旦某进程写入，就分裂成该进程自己的私有页。
因此“共享”主要发生在代码和只读数据，不是整个 DLL 全共享。
为什么你会听到“DLL 只加载一份”：

从磁盘文件角度：同一个 DLL 文件不会每个进程都重新复制成独立完整镜像。
从物理内存角度：大量只读页面确实被多个进程复用。
但从进程视角：每个进程都有自己的模块表、IAT 修正结果、TLS 状态、私有数据页。
再补一条和你注射器直接相关的点：

即便共享同一个 DLL 文件页，不同进程里模块基址可能不同（ASLR），所以函数虚拟地址不一定相同。
这就是手动映射时必须按“目标进程”重新算地址、修 IAT/重定位的根本原因。
```
DLL寻找与同名策略  
```text
结论先说：

PE 导入表通常只写模块名（比如 kernel32.dll），不写完整路径。
发生“同名 DLL”时，最终加载哪一个由 Windows 的 DLL 搜索与加载策略决定，不是 PE 自己决定。
现代系统会通过已加载模块表、KnownDLLs、系统目录优先级、SxS 清单、API Set 映射等机制尽量避免歧义和劫持。
简化理解“名字重复怎么办”：

先看进程里是否已经加载了同名模块
如果已加载，通常复用这个已加载模块实例（按加载器规则）。

没有的话，按搜索顺序找
顺序受很多因素影响，比如：

是否开启 SafeDllSearchMode
是否使用 SetDefaultDllDirectories / AddDllDirectory
应用目录、System32、PATH 等
是否有 Side-by-Side manifest 绑定特定版本
是否是 KnownDLL（内核预定义映射）
API Set 不是直接按文件名找
像 api-ms-win-* 这类会先映射到宿主模块（如 kernelbase/ucrtbase），再解析。
为什么这对你的注射器有影响：

你现在按模块名匹配远程模块，默认相信“同名即同实现”。
在大多数系统 DLL 场景这是可行的。
但如果目标进程里存在同名私有 DLL（例如插件目录里的 foo.dll），就可能匹配到“不是你预期”的那个。
工程上怎么降低风险：

尽量只依赖系统核心 DLL（kernel32/kernelbase/ntdll/user32 等）。
对关键模块做路径校验（比较远程模块完整路径是否在 System32）。
自己的依赖 DLL 用唯一名字，避免通用名冲突。
生产级实现会做更完整的“模块身份校验”（路径、签名、导出特征）。
所以你说得对：PE 只给“名字”，真正解决重名冲突的是 Windows 加载器策略和运行时上下文。
```