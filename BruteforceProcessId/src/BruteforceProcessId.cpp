#include <windows.h>
#include <stdio.h>
#include "./../../useful.h"

bool BruteforceProcessIds()
{
	HANDLE hProcess = NULL;
	DWORD dwExitCode = 0;
	ULONG ulHiddenProcesses = 0, ulScannedProccesses = 0;

	for ( DWORD dwProcessId = 0; dwProcessId < 0x83B8; dwProcessId += 4)
	{
		if ( dwProcessId == 0 || dwProcessId == 4 )
			continue;
	
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
		if ( hProcess == NULL )
		{
			if ( GetLastError() != ERROR_INVALID_PARAMETER )
			{
				// If the error code is other than 
				// ERROR_INVALID_PARAMETER that means this
				// process exists but we are not able to open.

				//check if this process is already discovered
				//using standard API functions.
				if( !ProcessExist(dwProcessId) )
				{
					printf("Hidden process found pid=%d\n", dwProcessId);
					ulHiddenProcesses++;
				}

			}
			continue;
		}

		ulScannedProccesses++;

		dwExitCode = 0;
		GetExitCodeProcess( hProcess, &dwExitCode );

		// check if this is active process...
		// only active process will return error 
		// code as ERROR_NO_MORE_ITEMS
		if( dwExitCode == ERROR_NO_MORE_ITEMS )  
		{
			//
			// check if this process is already discovered
			// process should not exist
			//
			if( !ProcessExist(dwProcessId) )
			{
				printf("Hidden process found pid=%d\n", dwProcessId);
				ulHiddenProcesses++;
			}
		}

		CloseHandle(hProcess);
	}

	return ulHiddenProcesses > 0 ? true : false;
}

int main(int argc, char* argv[])
{
	printf( "This method was first used by BlackLight and it turned out to be very effective yet simple."
		"Here, it enumerates through process id from 0 to 0x41DC and then check if that process exist by calling OpenProcess function."
		"Then this list of discovered processes are compared with normal process list got using standard enumeration functions (such as Process32First, EnumProcesses functions).\n");
	
	SetDebugPrivileges();
	BruteforceProcessIds();

	return 0;
}