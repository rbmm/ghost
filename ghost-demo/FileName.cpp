#include "stdafx.h"

#include "../ghost/ghost.h"

_NT_BEGIN

int ShowErrorBox(HWND hwnd, HRESULT dwError, PCWSTR pzCaption, UINT uType = MB_OK)
{
	PWSTR psz;
	ULONG dwFlags, errType = uType & MB_ICONMASK;
	HMODULE hmod;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
	__nt:
		static HMODULE s_hmod;
		if (!s_hmod)
		{
			s_hmod = GetModuleHandle(L"ntdll");
		}
		hmod = s_hmod;
		dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE;

		if (!errType)
		{
			static const UINT s_errType[] = { MB_ICONINFORMATION, MB_ICONINFORMATION, MB_ICONWARNING, MB_ICONERROR };
			uType |= s_errType[(ULONG)dwError >> 30];
		}
	}
	else
	{
		hmod = 0;
		dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM;
		if (!errType)
		{
			uType |= dwError ? MB_ICONERROR : MB_ICONINFORMATION;
		}
	}

	int r = IDCANCEL;
	if (FormatMessageW(dwFlags, hmod, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (PWSTR)&psz, 0, 0))
	{
		r = MessageBoxW(hwnd, psz, pzCaption, uType);
		LocalFree(psz);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return r;
}

NTSTATUS ReadFileToMem(_In_ PCWSTR lpFileName, _Out_ PDATA_BLOB pdb)
{
	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING ObjectName;

	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	NTSTATUS status;

	if (0 <= (status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0)))
	{
		status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb,
			FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			FILE_STANDARD_INFORMATION fsi;

			if (0 <= (status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
			{
				if (fsi.EndOfFile.QuadPart < 0x10000000) // 256 mb
				{
					if (pdb->pbData = (PBYTE)LocalAlloc(LMEM_FIXED, fsi.EndOfFile.LowPart))
					{
						if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, pdb->pbData, fsi.EndOfFile.LowPart, 0, 0)))
						{
							LocalFree(pdb->pbData);
						}
						else
						{
							pdb->cbData = (ULONG)iosb.Information;
						}
					}
					else
					{
						status = STATUS_NO_MEMORY;
					}
				}
				else
				{
					status = STATUS_FILE_TOO_LARGE;
				}
			}
			NtClose(hFile);
		}
	}

	return status;
}

NTSTATUS ReadCmd(_Out_ PDATA_BLOB pdb)
{
	WCHAR comspec[MAX_PATH];
	return GetEnvironmentVariableW(L"comspec", comspec, _countof(comspec)) 
		? ReadFileToMem(comspec, pdb) : RtlGetLastNtStatus();
}

void WINAPI ep(void*)
{
	NTSTATUS status = STATUS_VARIABLE_NOT_FOUND;
	WCHAR caption[64], *pszCaption = 0;
	PWSTR tmp = 0;
	ULONG cch = 0;
	while (cch = ExpandEnvironmentStringsW(L"%tmp%\\ghost", tmp, cch))
	{
		if (tmp)
		{
			DATA_BLOB db;
			if (0 <= (status = ReadCmd(&db)))
			{
				PROCESS_INFORMATION pi;
				STARTUPINFOW si = { sizeof(si) };
				// si.lpDesktop = const_cast<PWSTR>(L"Winsta0\\Default");
				si.lpTitle = const_cast<PWSTR>(L"####### tile");

				if (0 <= (status = GhCreateProcess(db.pbData, db.cbData, tmp, GetCommandLineW(), FALSE, CREATE_SUSPENDED, 
					0, 0, &si, &pi, NtCurrentProcess())))
				{
					NtClose(pi.hProcess);
					ResumeThread(pi.hThread);
					NtClose(pi.hThread);

					if (0 < swprintf_s(caption, _countof(caption), L"PID=%x(%u)", pi.dwProcessId, pi.dwProcessId))
					{
						pszCaption = caption;
					}
				}

				LocalFree(db.pbData);
			}
			break;
		}

		tmp = (PWSTR)alloca(cch * sizeof(WCHAR));
	}

	ShowErrorBox(0, status ? HRESULT_FROM_NT(status) : S_OK, pszCaption, MB_ICONINFORMATION);
	ExitProcess(status);
}

_NT_END