# ByeIntegrity — Windows UAC Bypass
Bypass User Account Control (UAC) to gain elevated (Administrator) privileges to run any program at a high integrity level.
![](example.gif)

## Requirements
- Administrator account
- UAC notification level set to default or lower

## 2021 Update
I have decided to update ByeIntegrity so that it's much faster, lightweight, and reliable. This is a significant overhaul so I've created a new project in the VS solution called "ByeIntegrity2021," which is the updated version of this attack. Of course, the original version is still there. For more information on the new version, expand the details below.

<details>
	<summary>Update information</summary>

---
The new version now is able to hijack the NIC without depending on the existing native images installed into the NIC. It does this by creating its own native image descriptors and payloads, then moving them into the NIC, eliminating the need for:
  
- Existing `*.ni` images produced by `NGEN.exe`
- Running the system maintenance tasks
- NIC directory traversal
- Long wait/run time
- Limited number of runs (before hijacked DLL runs out of space)
  
The CLR loads native images from the NIC by doing a recursive directory scan of each entry, and then reading its `*.aux` file. This file contains information about the native image, and its dependencies. Based off the information in the `AUX` file, the CLR will either load the image or reject it, and then move on to the next candidate. If no viable candidates are found, it loads the standard image and uses jit to compile it normally. No part of the actual native image is read (it is only checked for its existence), so ByeIntegrity simply places the payload DLL with the same name the native image would have.
  
The updated version of ByeIntegrity comes with a tool called **AUXGen**, which takes in the name of an assembly from the GAC and then generates its corresponding `AUX` file. The `AUX` file is generated so that it matches the CLR's checks and the CLR will load the "native image" which is described by the `AUX` file. Note: AUXGen does not handle dependencies when generating the `AUX` file. It only does as much as it needs to so that the CLR will load the image. I will post details of the `AUX` file format later.

ByeIntegrity now uses `ISecurityEditor`, just like UACMe does, which cuts down on the needed code. It also requires that you have generated the `AUX` file for the assembly `MMCEx`, and placed it in the same directory as ByeIntegrity. `MMCEx` is now the targeted image because of its load order and shorter name.
  
</details>

## How it works
ByeIntegrity hijacks a DLL located in the Native Image Cache (NIC). The NIC is used by the .NET Framework to store optimized .NET Assemblies that have been generated from programs like Ngen, the .NET Framework Native Image Generator. Because Ngen is usually run under the current user with Administrative privileges through the Task Scheduler, the NIC grants modify access for members of the Administrators group.

The Microsoft Management Console (MMC) Windows Firewall Snap-in uses the .NET Framework, and upon initializing it, modules from the NIC are loaded into the MMC process. The MMC executable uses AutoElevate, a mechanism Windows uses that automatically elevates a process’s token without UAC prompting.

ByeIntegrity hijacks a specific DLL located in the NIC named `Accessibility.ni.dll`. It writes some shellcode into an appropriately-sized area of padding located in the `.text` section of the DLL. The entry point of the DLL is then updated to point to the shellcode. Upon DLL load, the entry point (which is actually the shellcode) is executed. The shellcode calculates the address of `kernel32!CreateProcessW`, creates a new instance of `cmd.exe` running as an Administrator, and then simply returns `TRUE`. This is only for the `DLL_PROCESS_ATTACH` reason; all other reasons will immediately return `TRUE`.
## UACMe
This attack is implemented in UACMe as method #63. If you want to try out this attack, please, use UACMe first. The attack is the same, however, UACMe uses a different method to modify the NIC. ByeIntegrity uses `IFileOperation` while UACMe uses `ISecurityEditor`. In addition, UACMe chooses the correct `Accessibility.ni.dll` for your system and preforms the system maintenance tasks if necessary (to generate the NIC components). ByeIntegrity simply chooses the first NIC entry that exists (which may/may not be the correct entry that MMC is using) and does not run the system maintenance tasks. ByeIntegrity contains **significantly** more code than UACMe, so reading the UACMe implementation will be much easier to understand than reading the ByeIntegrity code. Lastly, ByeIntegrity launches a child process during the attack whereas UACMe does not.

**tl;dr: UACMe is simpler and more effective than ByeIntegrity, so use UACMe first.**
## Using the code
If you’re reading this then you probably know how to compile the source. Just note that this hasn’t been tested or designed with x86 in mind at all, and it probably won’t work on x86 anyways.

Just like UACMe, **I will never upload compiled binaries to this repo.** There are always people who want the world to crash and burn, and I'm not going to provide an easy route for them to run this on somebody else's computer and cause intentional damage. I also don't want script-kiddies to use this attack without understanding what it does and the damage it can cause.
## Supported Versions
This attack works from Windows 7 (7600) up until the latest version of Windows.