#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "useful.h"

/*
 * Sets debug privileges to current process.
*/
bool SetDebugPrivileges()
{
	HANDLE hToken;
	LUID LuidValue;
	TOKEN_PRIVILEGES tp;
	bool fResult = false;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &LuidValue))
		{
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = LuidValue;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
			{
				fResult = true;
			}
		}
		CloseHandle(hToken);
	}

	return fResult;
}


/*
 * Returns true if Process ID is found.
*/
bool GetProcessName(DWORD dwProcessId, wchar_t* szProcessName, size_t nMaxProcessName)
{
	bool fResult = false;
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 pe32 = { 0 };

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0 );
	if ( hSnapshot != INVALID_HANDLE_VALUE )
	{
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe32))
		{
			do 
			{
				if ( pe32.th32ProcessID == dwProcessId)
				{
					memset(szProcessName, 0, nMaxProcessName);
					wcsncpy_s(szProcessName, nMaxProcessName, pe32.szExeFile, __min(nMaxProcessName, wcslen(pe32.szExeFile)));
					fResult = true;
					break;
				}
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}


	return fResult;
}

/*
 * Returns true if process id has been found.
*/
bool ProcessExist(DWORD dwProcessId)
{
	bool fResult = false;
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 pe32 = { 0 };

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0 );
	if ( hSnapshot != INVALID_HANDLE_VALUE )
	{
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe32))
		{
			do 
			{
				if ( pe32.th32ProcessID == dwProcessId)
				{
					//
					// process found, abort
					//
					fResult = true;
					break;
				}
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}

	return fResult;
}


/*
 * Returns true if process name is csrss.exe
*/
bool IsCSRSSProcess(DWORD dwProcessId)
{
	wchar_t szName[ 0x100 ]= { 0 };

	if (GetProcessName(dwProcessId, szName, sizeof(szName)/sizeof(szName[0])))
	{
		if (_wcsicmp(L"csrss.exe", szName) == 0 )
			return true;
	}
	return false;
}

