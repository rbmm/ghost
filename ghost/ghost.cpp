#include "../inc/stdafx.h"

#include "ghost.h"

_NT_BEGIN

//
// NtCreateProcessEx flags
//
#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008
#define PROCESS_CREATE_FLAGS_LARGE_PAGES 0x00000010

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateProcessEx(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ParentProcess,
	_In_ ULONG Flags,
	_In_opt_ HANDLE SectionHandle,
	_In_opt_ HANDLE DebugPort,
	_In_opt_ HANDLE ExceptionPort,
	_In_ ULONG JobMemberLevel
);

EXTERN_C
NTSTATUS
WINAPI
GhCreateProcess(
	_In_ PVOID pvExe,
	_In_ ULONG cbExe,
	_In_ PCWSTR lpApplicationName,
	_In_opt_ PCWSTR lpCommandLine,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ PVOID lpEnvironment,
	_In_opt_ PCWSTR lpCurrentDirectory,
	_In_ STARTUPINFOW* lpStartupInfo,
	_Out_ PPROCESS_INFORMATION lpProcessInformation,
	_In_opt_ HANDLE ParentProcess) // = NtCurrentProcess() | must have PROCESS_CREATE_PROCESS
{
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = RtlGetCurrentPeb()->ProcessParameters;

	if (!lpEnvironment)
	{
		lpEnvironment = ProcessParameters->Environment;
	}

	NTSTATUS status;
	UNICODE_STRING ImagePathName, CommandLine, CurrentDirectory, WindowTitle, DesktopInfo;

	if (0 <= (status = RtlInitUnicodeStringEx(&ImagePathName, lpApplicationName)) &&
		0 <= (status = RtlInitUnicodeStringEx(&CommandLine, lpCommandLine)) &&
		0 <= (status = RtlInitUnicodeStringEx(&CurrentDirectory, lpCurrentDirectory)) &&
		0 <= (status = RtlInitUnicodeStringEx(&WindowTitle, lpStartupInfo->lpTitle)) &&
		0 <= (status = RtlInitUnicodeStringEx(&DesktopInfo, lpStartupInfo->lpDesktop)) &&
		0 <= (status = RtlCreateProcessParameters(&ProcessParameters, &ImagePathName,
			&ProcessParameters->DllPath,
			lpCurrentDirectory ? &CurrentDirectory : &ProcessParameters->CurrentDirectory.DosPath,
			&CommandLine, lpEnvironment, &WindowTitle, &DesktopInfo, 0, 0)))
	{
		//
		// Push the parameters into the new process
		//

		ProcessParameters->StartingX = lpStartupInfo->dwX;
		ProcessParameters->StartingY = lpStartupInfo->dwY;
		ProcessParameters->CountX = lpStartupInfo->dwXSize;
		ProcessParameters->CountY = lpStartupInfo->dwYSize;
		ProcessParameters->CountCharsX = lpStartupInfo->dwXCountChars;
		ProcessParameters->CountCharsY = lpStartupInfo->dwYCountChars;
		ProcessParameters->FillAttribute = lpStartupInfo->dwFillAttribute;
		ProcessParameters->WindowFlags = lpStartupInfo->dwFlags;
		ProcessParameters->ShowWindowFlags = lpStartupInfo->wShowWindow;

		if (lpStartupInfo->dwFlags & STARTF_USESTDHANDLES) {
			ProcessParameters->StandardInput = lpStartupInfo->hStdInput;
			ProcessParameters->StandardOutput = lpStartupInfo->hStdOutput;
			ProcessParameters->StandardError = lpStartupInfo->hStdError;
		}

		HANDLE hFile, hSection = 0;
		IO_STATUS_BLOCK iosb;

		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ImagePathName, OBJ_CASE_INSENSITIVE };

		if (0 <= (status = RtlDosPathNameToNtPathName_U_WithStatus(lpApplicationName, &ImagePathName, 0, 0)))
		{
			status = NtCreateFile(&hFile, SYNCHRONIZE | FILE_EXECUTE | FILE_APPEND_DATA | DELETE, &oa, &iosb, 0, 0, 0,
				FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, 0, 0);

			RtlFreeUnicodeString(&ImagePathName);

			if (0 <= status)
			{
				static const FILE_DISPOSITION_INFORMATION fdi = { TRUE };

				0 <= (status = NtSetInformationFile(hFile, &iosb, (void*)&fdi, sizeof(fdi), FileDispositionInformation)) &&
					0 <= (status = NtWriteFile(hFile, 0, 0, 0, &iosb, pvExe, cbExe, 0, 0)) &&
					0 <= (status = NtCreateSection(&hSection, SECTION_MAP_EXECUTE | SECTION_QUERY, 0, 0, PAGE_EXECUTE, SEC_IMAGE, hFile));

				NtClose(hFile);

				if (0 <= status)
				{
					PVOID BaseAddress = 0;
					SECTION_IMAGE_INFORMATION sii;

					HANDLE hProcess = 0, hThread;

					if (0 <= (status = ZwQuerySection(hSection, SectionImageInformation, &sii, sizeof(sii), 0)))
					{
						status = NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, 0, ParentProcess,
							bInheritHandles ? PROCESS_CREATE_FLAGS_INHERIT_HANDLES : 0,
							hSection, 0, 0, FALSE);
					}

					NtClose(hSection);

					if (0 <= status)
					{
						PROCESS_BASIC_INFORMATION pbi;

						if (0 <= (status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0)))
						{
							SIZE_T rva = RtlPointerToOffset(ProcessParameters, ProcessParameters->Environment);
							SIZE_T Size = ProcessParameters->EnvironmentSize + rva, ViewSize = Size;

							if (0 <= (status = ZwAllocateVirtualMemory(hProcess, &(BaseAddress = 0), 0,
								&ViewSize, MEM_COMMIT, PAGE_READWRITE)))
							{
								CLIENT_ID cid;
								ProcessParameters->Environment = (PBYTE)BaseAddress + rva;

								if (0 <= (status = ZwWriteVirtualMemory(hProcess, BaseAddress, ProcessParameters, Size, 0)) &&
									0 <= (status = ZwWriteVirtualMemory(hProcess, &reinterpret_cast<PEB*>(pbi.PebBaseAddress)->ProcessParameters, &BaseAddress, sizeof(PVOID), 0)) &&
									0 <= (status = RtlCreateUserThread(hProcess, 0,
										(dwCreationFlags & CREATE_SUSPENDED) != 0, 0, 0, 0, sii.TransferAddress, 0, &hThread, &cid)))
								{
									lpProcessInformation->dwProcessId = (ULONG)(ULONG_PTR)cid.UniqueProcess;
									lpProcessInformation->dwThreadId = (ULONG)(ULONG_PTR)cid.UniqueThread;
									lpProcessInformation->hThread = hThread;
									lpProcessInformation->hProcess = hProcess;

									goto __ok;
								}
							}
						}

						NtClose(hProcess);
					}
				}
			}
		}
	__ok:

		RtlDestroyProcessParameters(ProcessParameters);
	}

	return status;
}

_NT_END