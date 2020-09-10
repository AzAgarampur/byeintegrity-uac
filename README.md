# Bypass UAC by using Windows AutoElevate feature and modifying a system DLL
## How it works
Windows uses a mechanism called AutoElevate to raise the integrity level of the current process token to high without UAC prompting. This is used for signed Windows binaries in the system directory.

Windows Firewall Settings uses the Microsoft Management Console `mmc.exe`. `mmc.exe` is an AutoElevate executable, meaning, even when it is launched as a normal user, if possible, it attempts to gain administrative privileges. When `mmc.exe` is launched with `%WinDir%\System32\WF.msc`, the .NET framework execution engine is
initialized. .NET assemblies are the loaded into `mmc.exe`

In the Windows assembly cache, `%WinDir%\assembly`, a folder contains the file `Accessibility.ni.dll`. This file has full access by administrators. **This is one of the files that `mmc.exe` loads when loading the Firewall snap-in.**
This attack works by modifying the file -- it writes some shellcode to the file and changes its entry point to the shellcode. Think of the shellcode as `DllMain`.
Therefore, as this module is loaded into `mmc.exe,` `DllMain` is called, and executes the shellcode. This shellcode launches an instance of `cmd.exe`, as an administrator.

It's interesting that `Accessibility.ni.dll` has these permissions. In addition, it does not have a checksum set in the `IMAGE_OPTIONAL_HEADER`, nor does it appear to be a signed file.

## What's in this repo
This repository contains the code for this attack. **AMD64 ONLY**. It will attempt to locate your specific version of `Accessibility.ni.dll`, patch it, and launch the Firewall Settings via `ShellExecuteW` with `WF.msc`.

---

The code is written in C++ and uses the C++ standard library for string handling and such. It uses the Win32 API. (Not the NTAPI, I just wanted a working, reliable sample.) The ASM source for the shellcode is located in `shellcode.txt` *Note: the `int 3` is not included in the actual program source, but is in `shellcode.txt`.*
**`IFileOperation` is used to modify directories; thanks `hfiref0x/UACME` for the source that allowed me to learn how to do this.**

## Tested versions
This has been developed and tested on **only Windows 10 Version 2004 (Build 10.0.19042).** Technically, it should work all the way from Windows 7. However, `shfusion.dll` does not allow modifying files in the assembly cache folder. Every version of Windows 10 does not have this registered, so it should work with all Windows 10 versions. Previous versions of Windows without `Desktop.ini` in the assembly cache folder will also work.
