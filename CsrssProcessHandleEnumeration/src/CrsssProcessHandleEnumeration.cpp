#include <windows.h>
#include <stdio.h>
#include "./../../useful.h"

NTQUERYSYSTEMINFORMATION NtQuerySystemInformation;

//
// Csrss contains a list of all running processes.
// We get this list of running processes and compare it with the normal windows API from tlhelp32 (Process32First and Process32Next)
//

bool CsrssProcessHandleEnumeration()
{
	NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if ( NtQuerySystemInformation == NULL )
		return false;

	LPBYTE pBufHandleTable = NULL;
	DWORD dwHandleTableSize = 0x100000;
	SYSTEM_HANDLE_INFORMATION* pHandleInformation = NULL;
	ULONG ulHiddenProcesses = 0, ulScannedProccesses = 0;

	pBufHandleTable = new BYTE[ dwHandleTableSize ];

	NtQuerySystemInformation(SystemHandleInformation, (PDWORD)pBufHandleTable, dwHandleTableSize, NULL);
	pHandleInformation = (SYSTEM_HANDLE_INFORMATION*)pBufHandleTable;

	for(ULONG i = 0; i< pHandleInformation->HandleCount; i++)
	{
		DWORD dwProcessId = pHandleInformation->Handles[i].ProcessId;

		if(pHandleInformation->Handles[i].ObjectTypeNumber == HANDLE_TYPE_PROCESS) 
		{
			if ( IsCSRSSProcess(dwProcessId) )
			{
				// printf( "type: %08x, handle: %08x\n", pHandleInformation->Handles[i].ObjectTypeNumber, pHandleInformation->Handles[i].Handle);

				//
				// ok current process is csrss, now duplicate all process id's and look with normal windows API if process is found
				// 
				HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwProcessId);
				if ( hProcess != NULL )
				{
					HANDLE hTarget = NULL;
					if ( DuplicateHandle(hProcess, (HANDLE)pHandleInformation->Handles[i].Handle, GetCurrentProcess(), &hTarget, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, 0) )
					{
						DWORD dwTargetId = GetProcessId(hTarget);
						if ( dwTargetId != (DWORD)-1 )
						{
							ulScannedProccesses++;

							// 
							// let's see if process is hidden for normal windows API
							//
							if ( !ProcessExist(dwTargetId) )
							{
								printf( "Found hidden process %u\n", dwTargetId );
								ulHiddenProcesses++;
							}
						}
						CloseHandle(hTarget);
					}
					CloseHandle(hProcess);
				}
			}
		}
	}

	delete[] pBufHandleTable;

	return ulHiddenProcesses > 0 ? true : false;
}

int main(int argc, char* argv[])
{
	printf( "Any windows process when run will have lot of open handles related to process, thread, named objects, file, port, registry, etc. that can be used to detect hidden process."
		"One can use the native API function. The effective way to enumerate handles is to use NtQuerySystemInformation with first parameter as SystemHandleInformation."
		"It lists the handles from all running processes in the system. For each enumerated handle, it provides information such as handle, handle type and process id of the owning process." 
		"Hence, by enumerating through all the handles and then using the associated process id, one can detect all possible hidden processes that are not revealed through standard API functions.\n" );


	SetDebugPrivileges();
	CsrssProcessHandleEnumeration();

	return 0;
}

