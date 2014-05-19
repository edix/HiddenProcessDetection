#pragma once


/* The following structure is actually called SYSTEM_HANDLE_TABLE_ENTRY_INFO, but SYSTEM_HANDLE is shorter. */
typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount; /* Or NumberOfHandles if you prefer. */
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


#define SystemProcessInformation 5
#define SystemHandleInformation 16

// For XP & 2K3 : HANDLE_TYPE_PROCESS = 0x5
// For Vista & Longhorn : HANDLE_TYPE_PROCESS = 0x6
// Windows 8: HANDLE_TYPE_PROCESS = 0x7
#define HANDLE_TYPE_PROCESS 7


typedef DWORD (CALLBACK* NTQUERYSYSTEMINFORMATION)( DWORD , PDWORD , DWORD , PVOID );


bool SetDebugPrivileges();
bool ProcessExist(DWORD dwProcessId);
bool GetProcessName(DWORD dwProcessId, wchar_t* szProcessName, size_t nMaxProcessName);
bool IsCSRSSProcess(DWORD dwProcessId);
