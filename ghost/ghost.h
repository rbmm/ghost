#pragma once

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
	_In_opt_ HANDLE ParentProcess); // = NtCurrentProcess() | must have PROCESS_CREATE_PROCESS

