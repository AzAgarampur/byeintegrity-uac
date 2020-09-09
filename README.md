# Bypass UAC by using Windows AutoElevate feature and modifying a system DLL
## How it works
Windows uses a mechanism called AutoElevate to raise the integrity level of the current process token to high without UAC prompting. This is used for signed Windows binaries in the system directory.

Windows Event Viewer uses the Microsoft Management Console `mmc.exe`. `mmc.exe` is an AutoElevate executable, meaning, even when it is launched as a normal user, if possible, it attempts to gain administrative privileges. When `mmc.exe` is launched with `%WinDir%\System32\eventvwr.msc`, the .NET framework execution engine is
initialized. .NET assemblies are the loaded into `mmc.exe`

In the Windows assembly cache, `%WinDir%\assembly`, a folder contains the file `EventViewer.ni.dll`. This file has full access by administrators. **This is one of the files that `mmc.exe` loads when loading the Event Viewer.**
This attack works by modifying the file -- it writes some shellcode to the file and changes its entry point to the shellcode. Think of the shellcode as `DllMain`.
Therefore, as this module is loaded into `mmc.exe,` `DllMain` is called, and executes the shellcode. This shellcode launches an instance of `cmd.exe`, as an administrator.

It's interesting that `EventViewer.ni.dll` has these permissions. In addition, it does not have a checksum set in the `IMAGE_OPTIONAL_HEADER`, nor does it appear to be a signed file.

## What's in this repo
This repository contains the code for this attack. **AMD64 ONLY**. It will attempt to locate your specific version of `EventViewer.ni.dll`, patch it, and launch the Event Viewer via `ShellExecuteW` with `eventvwr.exe`.

---

The code is written in C++ and uses the C++ standard library for string handling and such. It uses the Win32 API. (Not the NTAPI, I just wanted a working, reliable sample.) The ASM source for the shellcode is located in `shellcode.txt` *Note: the `int 3` is not included in the actual program source, but is in `shellcode.txt`.*
**`IFileOperation` is used to modify directories; thanks `hfiref0x/UACME` for the source that allowed me to learn how to do this.**
