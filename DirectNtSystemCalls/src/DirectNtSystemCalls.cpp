#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include "./../../useful.h"

DWORD g_dwMajorVersion = 0;
DWORD g_dwMinorVersion = 0;

#define SystemProcessInformation 5

__declspec(naked) NTSTATUS __stdcall DirectNTQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)	
{
	if( g_dwMajorVersion == 5 )
	{
		if (g_dwMinorVersion == 0)
		{
			//For Windows 2000
			__asm
			{
				mov eax, 0x97
				lea edx, dword ptr ss:[esp+4]
				int 0x2E
				ret 0x10
			}
		}
		else if (g_dwMinorVersion == 1)
		{
			// Windows XP
			__asm
			{
				mov eax, 0xAD     
				call SystemCall_XP
				ret 0x10

				SystemCall_XP:
				mov edx, esp
				_emit 0x0f
				_emit 0x34 //sysenter opcodes...
			}
		}
	}	

	//For Windows Vista & Longhorn
	else if (g_dwMajorVersion == 6)
	{
		if (g_dwMinorVersion == 0)
		{
			__asm
			{
				mov eax, 0xF8    
				call SystemCall_VISTA
				ret 0x10

				SystemCall_VISTA:
				mov edx, esp
				_emit 0x0f
				_emit 0x34 //sysenter opcodes...
			}
		}
		else if (g_dwMinorVersion == 1)
		{
			// Windows 7
			__asm
			{
				mov eax, 0x105    
				call SystemCall_WIN7
				ret 0x10

				SystemCall_WIN7:
				mov edx, esp
				_emit 0x0f
				_emit 0x34 //sysenter opcodes...
			}
		}
		else if (g_dwMinorVersion == 2)
		{
			//
			// Windows 8 Wow64 only, you guys need to implement this for every type of windows, like windows 8 x64 and windows 8 wow64
			// http://www.ffri.jp/assets/files/research/research_papers/psj10-murakami_EN.pdf
			//

			__asm
			{
				mov eax, 0x34
				xor ecx, ecx
				lea edx, [esp+4]
				call dword ptr fs:[0x0c0]
				ret 0x10
			}

		}
	}

	//
	// clean stack up
	//
	__asm 
	{
		ret 0x10
	}
}

bool CheckProcessesWithDirectSystemCall()
{
	OSVERSIONINFO os = { 0 };
	ULONG ulReturnLength = 0;
	LPBYTE pProcessList = NULL;
	SYSTEM_PROCESS_INFORMATION* pCurrentElement = NULL;
	wchar_t szProcessName[ 0x100 ] = { 0 };
	ULONG ulHiddenProcesses = 0, ulScannedProccesses = 0;

	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if (!GetVersionEx(&os))
	{
		return false;
	}

	g_dwMajorVersion = os.dwMajorVersion;
	g_dwMinorVersion = os.dwMinorVersion;

	DirectNTQuerySystemInformation(SystemProcessInformation, NULL, 0, &ulReturnLength);

	if ( ulReturnLength <= 0)
	{
		return false;
	}

	pProcessList = new BYTE[ ulReturnLength ];

	if ( pProcessList )
	{
		DirectNTQuerySystemInformation(SystemProcessInformation, pProcessList, ulReturnLength, &ulReturnLength);
		if ( ulReturnLength > 0 )
		{
			pCurrentElement = (SYSTEM_PROCESS_INFORMATION*)pProcessList;
			while (TRUE)
			{
				ulScannedProccesses++;

				//
				// todo: make one snapshot before and compare them both here (right now we are always creating a snapshot... and if a process closes right now we might think its hidden)
				//
				if ( !ProcessExist((DWORD)pCurrentElement->UniqueProcessId) )
				{
					printf( "Found hidden process (or not running anymore): process id=%u\n", pCurrentElement->UniqueProcessId);
					ulHiddenProcesses++;
				}

				pCurrentElement = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)pCurrentElement + pCurrentElement->NextEntryOffset);

				if ( pCurrentElement->NextEntryOffset == 0 )
					break;
			}
		}
	}

	delete[] pProcessList;

	printf( "Done. Scanned %u processes.\n", ulScannedProccesses);

	return ulHiddenProcesses > 0 ? true : false;
}

int main(int argc, char* argv[])
{
	printf( "This is very effective method to detect any hidden userland rootkit processes."
		"One of the lesser-known methods of enumerating the processes is to use NtQuerySystemInformation function by passing first parameter as SystemProcessesAndThreadsInformation."
		"The drawback of this method is that it can be easily circumvented by hooking the NtQuerySystemInformation function and then by tampering with the results.\n");

	SetDebugPrivileges();
	CheckProcessesWithDirectSystemCall();

	return 0;
}