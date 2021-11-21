#include <Windows.h>
#include <fusion.h>
#include <iostream>
#include <string>
#include <memory>
#include <bitset>
#include <ShlObj.h>
#include <wrl.h>
using Microsoft::WRL::ComPtr;

template <class T, class D>
inline D AlignTo(D data)
{
	auto mask{ static_cast<D>(sizeof(T)) - 1 };
	return (data + mask) & ~mask;
}

/* .NET CLR Runtime data structures and parsing information
*	Information has been referenced from the following source:
*	https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf
*/

typedef struct
{
	ULONG Signature;
	USHORT MajorVersion;
	USHORT MinorVersion;
	ULONG Reserved;
	ULONG Length;
} METADATA_ROOT, * PMETADATA_ROOT;

typedef struct
{
	ULONG Offset;
	ULONG Size;
	CHAR Name[ANYSIZE_ARRAY];
} METADATA_STREAM_HEADER, * PMETADATA_STREAM_HEADER;

typedef struct
{
	USHORT Flags;
	USHORT Streams;
	METADATA_STREAM_HEADER StreamHeaders[ANYSIZE_ARRAY];
} METADATA_ENDDATA, * PMETADATA_ENDDATA;

typedef struct
{
	ULONG Reserved0;
	BYTE MajorVersion;
	BYTE MinorVersion;
	BYTE HeapSizes;
	BYTE Reserved1;
	ULONG64 Valid;
	ULONG64 Sorted;
	ULONG Rows[ANYSIZE_ARRAY];
} LOGICAL_METADATA_STREAM, * PLOGICAL_METADATA_STREAM;

int wmain(
	int argc,
	WCHAR* argv[]
)
{
	if (argc < 2)
	{
		std::cout << "Usage: AUXGen <name>\n";
		return 0;
	}

	PWSTR winDir;
	auto hr{ SHGetKnownFolderPath(FOLDERID_Windows, 0, nullptr, &winDir) };
	if (FAILED(hr))
	{
		std::wcout << L"SHGetKnownFolderPath() failed. Error: 0x" << std::hex << hr << std::endl;
		return 1;
	}
	std::wstring path{ winDir };
	path += L"\\Microsoft.NET\\Framework64\\v4.0.30319\\";
	CoTaskMemFree(winDir);

	std::wstring currentDir;
	DWORD dirSize;
	if (!(dirSize = GetCurrentDirectoryW(0, nullptr)))
	{
		std::wcout << L"GetCurrentDirectoryW() (0) failed. Error: " << GetLastError() << std::endl;
		return 1;
	}
	currentDir.resize(dirSize);
	if (!(dirSize = GetCurrentDirectoryW(dirSize, &currentDir[0])))
	{
		std::wcout << L"GetCurrentDirectoryW() (1) failed. Error: " << GetLastError() << std::endl;
		return 1;
	}

	if (!SetCurrentDirectoryW(path.c_str()))
	{
		std::wcout << "SetCurrentDirectoryW() (0) failed. Error: " << GetLastError() << std::endl;
		return 1;
	}

	ComPtr<IAssemblyEnum> asmEnum;
	hr = CreateAssemblyEnum(&asmEnum, nullptr, nullptr, ASM_CACHE_GAC, nullptr);
	if (FAILED(hr))
	{
		std::cout << "CreateAssemblyEnum() failed. Error: 0x" << std::hex << hr << std::endl;
		return 1;
	}

	ComPtr<IAssemblyCache> asmCache;
	hr = CreateAssemblyCache(&asmCache, 0);
	if (FAILED(hr))
	{
		std::cout << "CreateAssemblyCache() failed. Error: 0x" << std::hex << hr << std::endl;
		return 1;
	}

	ComPtr<IAssemblyName> asmName;
	std::wstring name;
	while ((hr = asmEnum->GetNextAssembly(nullptr, &asmName, 0)) == S_OK)
	{
		DWORD nameSize{};
		hr = asmName->GetName(&nameSize, nullptr);
		if (hr != 0x8007007a && FAILED(hr))
		{
			asmName->Finalize();
			std::wcout << L"IAssemblyName::GetName() (0) failed. Error: 0x" << std::hex << hr << std::endl;
			return 1;
		}

		name.resize(nameSize - 1);
		hr = asmName->GetName(&nameSize, &name[0]);
		if (FAILED(hr))
		{
			asmName->Finalize();
			std::wcout << L"IAssemblyName::GetName() (1) failed. Error: 0x" << std::hex << hr << std::endl;
			return 1;
		}

		if (wcscmp(argv[1], name.c_str()) == 0)
			break;
		asmName->Finalize();
	}
	if (FAILED(hr))
	{
		std::wcout << L"IAssemblyEnum::GetNextAssembly() failed. Error: 0x" << std::hex << hr << std::endl;
		return 1;
	}
	if (hr == S_FALSE)
	{
		std::wcout << L"'" << argv[1] << L"' not found in GAC\n";
		return 0;
	}

	DWORD len{};
	hr = asmName->GetDisplayName(nullptr, &len, 0);
	if (hr != 0x8007007a && FAILED(hr))
	{
		asmName->Finalize();
		std::wcout << L"IAssemblyName::GetDisplayName() (0) failed. Error: 0x" << std::hex << hr << std::endl;
		return 1;
	}

	std::wstring displayName;
	displayName.resize(len - 1);
	hr = asmName->GetDisplayName(&displayName[0], &len, 0);
	asmName->Finalize();
	if (FAILED(hr))
	{
		std::wcout << L"IAssemblyName::GetDisplayName() (1) failed. Error: 0x" << std::hex << hr << std::endl;
		return 1;
	}

	ASSEMBLY_INFO asmInfo{};
	asmInfo.cbAssemblyInfo = sizeof ASSEMBLY_INFO;
	hr = asmCache->QueryAssemblyInfo(0, name.c_str(), &asmInfo);
	if (hr != 0x8007007a && FAILED(hr))
	{
		std::wcout << L"IAssemblyCache::QueryAssemblyInfo() (0) failed. Error: 0x" << std::hex << hr << std::endl;
		return 1;
	}

	std::wstring asmPath;
	asmPath.resize(asmInfo.cchBuf - 1);
	asmInfo.pszCurrentAssemblyPathBuf = &asmPath[0];
	hr = asmCache->QueryAssemblyInfo(0, name.c_str(), &asmInfo);
	if (FAILED(hr))
	{
		std::wcout << L"IAssemblyCache::QueryAssemblyInfo() (1) failed. Error: 0x" << std::hex << hr << std::endl;
		return 1;
	}

	/*
	 * I would use the .NET unmanaged metadata COM interfaces to get the MVID,
	 * however that requres .NET framework 3.5 which is not installed by default
	 * on most systems, so instead I will manually parse the .NET directory of the
	 * assembly and read the MVID that way.
	 */

	std::unique_ptr<void, decltype(&CloseHandle)> fileHandle{
		CreateFileW(asmInfo.pszCurrentAssemblyPathBuf, FILE_READ_ACCESS, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, nullptr),
		CloseHandle
	};
	if (fileHandle.get() == INVALID_HANDLE_VALUE)
	{
		std::wcout << L"CreateFileW() failed. Error: " << GetLastError() << std::endl;
		return 1;
	}

	std::unique_ptr<void, decltype(&CloseHandle)> mapping{
		CreateFileMappingW(fileHandle.get(), nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr),
		CloseHandle
	};
	if (!mapping)
	{
		std::wcout << L"CreateFileMapping() failed. Error: " << GetLastError() << std::endl;
		return 1;
	}

	std::unique_ptr<void, decltype(&UnmapViewOfFile)> file{
		MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0),
		UnmapViewOfFile
	};
	if (!file)
	{
		std::wcout << L"MapViewOfFile() failed. Error: " << GetLastError() << std::endl;
		return 1;
	}

	auto corHeader{ reinterpret_cast<PIMAGE_COR20_HEADER>(
		reinterpret_cast<PBYTE>(file.get()) +
		reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<PBYTE>(file.get())
			+ reinterpret_cast<PIMAGE_DOS_HEADER>(file.get())->e_lfanew)
			->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress
		) };
	auto metadataRoot{
		reinterpret_cast<PMETADATA_ROOT>(reinterpret_cast<PBYTE>(file.get()) + corHeader->MetaData.VirtualAddress)
	};
	auto streamData{
		reinterpret_cast<PMETADATA_ENDDATA>(reinterpret_cast<PBYTE>(metadataRoot)
		+ sizeof METADATA_ROOT + AlignTo<ULONG>(metadataRoot->Length))
	};

	PMETADATA_STREAM_HEADER streamHeader{ streamData->StreamHeaders }, metaStream{}, guidStream{}, stringStream{};
	bool foundStream{}, foundGuids{}, foundStrings{};
	for (auto i = 1; i < streamData->Streams; ++i)
	{
		if (foundStream && foundGuids && foundStrings)
			break;
		if (strcmp(streamHeader->Name, "#~") == 0)
		{
			foundStream = true;
			metaStream = streamHeader;
		}
		else if (strcmp(streamHeader->Name, "#GUID") == 0)
		{
			foundGuids = true;
			guidStream = streamHeader;
		}
		else if (strcmp(streamHeader->Name, "#Strings") == 0)
		{
			foundStrings = true;
			stringStream = streamHeader;
		}
		streamHeader = reinterpret_cast<PMETADATA_STREAM_HEADER>(
			reinterpret_cast<PBYTE>(streamHeader) + FIELD_OFFSET(METADATA_STREAM_HEADER, Name)
			+ AlignTo<ULONG>(strlen(streamHeader->Name) + 1));
	}
	if (!foundStream)
	{
		std::wcout << L"CLI #~ stream not found\n";
		return 1;
	}
	if (!foundGuids)
	{
		std::wcout << L"CLI #GUID stream not found\n";
		return 1;
	}
	if (!foundStrings)
	{
		std::wcout << L"CLI #Strings stream not found\n";
		return 1;
	}

	auto logicalMetadata{
		reinterpret_cast<PLOGICAL_METADATA_STREAM>(reinterpret_cast<PBYTE>(metadataRoot)
		+ metaStream->Offset)
	};
	std::bitset<64> validBits{ logicalMetadata->Valid };
	std::bitset<8> heapSizeBits{ logicalMetadata->HeapSizes };

	if (!validBits[0])
	{
		std::wcout << L"Module table does not seem to be present in metadata\n";
		return 1;
	}

	if (logicalMetadata->Rows[0] > 1)
		std::wcout << L"More than one Module entry exists, using the first one\n";

	auto tables{
		reinterpret_cast<PBYTE>(logicalMetadata) + FIELD_OFFSET(LOGICAL_METADATA_STREAM, Rows)
		+ (validBits.count() * sizeof ULONG)
	};

	ULONG mvidIndex, modNameIndex;
	tables += 2;
	if (heapSizeBits[0])
	{
		modNameIndex = *reinterpret_cast<PULONG>(tables);
		tables += 4;
	}
	else
	{
		modNameIndex = *reinterpret_cast<PUSHORT>(tables);
		tables += 2;
	}
	if (heapSizeBits[1])
		mvidIndex = *reinterpret_cast<PULONG>(tables);
	else
		mvidIndex = *reinterpret_cast<PUSHORT>(tables);

	auto guids{
		reinterpret_cast<LPGUID>(reinterpret_cast<PBYTE>(metadataRoot) + guidStream->Offset)
	};

	std::string modName{ reinterpret_cast<char*>(reinterpret_cast<PBYTE>(metadataRoot)
		+ stringStream->Offset + modNameIndex) };

	auto extensionPos{ modName.find_last_of('.') };
	if (extensionPos != std::string::npos)
		modName.insert(extensionPos, ".ni");
	else
		modName += ".ni";

	modName += ".aux";

	if (!SetCurrentDirectoryW(currentDir.c_str()))
	{
		std::wcout << L"SetCurrentDirectoryW() (1) failed. Error: " << GetLastError() << std::endl;
		return 1;
	}

	auto auxSize{ 100 + AlignTo<ULONG>(len) };
	auto auxData{ std::make_unique<BYTE[]>(auxSize) };
	auto dataPtr{ reinterpret_cast<PULONG>(auxData.get()) };
	std::unique_ptr<void, decltype(&CloseHandle)> auxFile{
		CreateFileA(modName.c_str(), FILE_WRITE_ACCESS, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr),
		CloseHandle
	};
	if (auxFile.get() == INVALID_HANDLE_VALUE)
	{
		std::wcout << L"CreateFileA() failed. Error: " << GetLastError() << std::endl;
		return 1;
	}

	std::string displayNameAnsi;
	displayNameAnsi.resize(len - 1);
	if (!WideCharToMultiByte(
		CP_ACP,
		0,
		displayName.c_str(),
		len,
		&displayNameAnsi[0],
		static_cast<int>(displayNameAnsi.capacity()),
		nullptr,
		nullptr
	))
	{
		std::wcout << L"WideCharToMultiByte() failed. Error: " << GetLastError() << std::endl;
		return 1;
	}

	*dataPtr++ = 0x5;
	*dataPtr++ = auxSize - 8;
	*dataPtr++ = 0xB;
	*dataPtr++ = auxSize - 16;
	*dataPtr++ = 0xD;
	*dataPtr++ = auxSize - 100;
	memcpy(dataPtr, displayNameAnsi.c_str(), displayNameAnsi.length() + 1);

	auto delta{ (auxSize - 100) - (displayNameAnsi.length() + 1) };
	if (delta)
	{
		auto ptr{
			reinterpret_cast<PBYTE>(reinterpret_cast<PBYTE>(dataPtr) + displayNameAnsi.length() + 1)
		};
		for (auto i = 1; i <= delta; ++i)
		{
			*ptr++ = 0xCC;
		}
	}

	dataPtr = reinterpret_cast<PULONG>(reinterpret_cast<PBYTE>(dataPtr) + delta + 1 + displayNameAnsi.length());
	*dataPtr++ = 0x7;
	*dataPtr++ = 0x4;
	*dataPtr++ = 0x1109;
	*dataPtr++ = 0x2;
	*dataPtr++ = 0x8;
	*dataPtr++ = 0;
	*dataPtr++ = 0;
	*dataPtr++ = 0xF;
	*dataPtr++ = 0x4;
	*dataPtr++ = 0;
	*dataPtr++ = 0x10;
	*dataPtr++ = 0x4;
	*dataPtr++ = 0x1;
	*dataPtr++ = 0x9;
	*dataPtr++ = 0x10;
	memcpy(dataPtr, &guids[mvidIndex - 1], sizeof GUID);

	if (!WriteFile(auxFile.get(), auxData.get(), auxSize, &len, nullptr))
	{
		std::wcout << L"WriteFile() failed. Error: " << GetLastError() << std::endl;
		return 1;
	}

	auto stdHandle{ GetStdHandle(STD_OUTPUT_HANDLE) };

	SetConsoleTextAttribute(stdHandle, 15);

	std::wcout << L"\nAUX file";

	SetConsoleTextAttribute(stdHandle, 14);

	std::cout << " '" << modName << "'";

	SetConsoleTextAttribute(stdHandle, 15);

	std::wcout << L" generated successfully.\n";

	SetConsoleTextAttribute(stdHandle, 7);

	return 0;
}