#include "Fltkernel.h"
#ifndef _INFO_H

#define _INFO_H

extern const int MAX_COUNT_ENTRY;
#ifdef WIN32
	
#else

#define  BYTE UCHAR
/*
nt!_EX_PUSH_LOCK
+ 0x000 Locked           : Pos 0, 1 Bit
+ 0x000 Waiting : Pos 1, 1 Bit
+ 0x000 Waking : Pos 2, 1 Bit
+ 0x000 MultipleShared : Pos 3, 1 Bit
+ 0x000 Shared : Pos 4, 60 Bits
+ 0x000 Value : Uint8B
+ 0x000 Ptr : Ptr64 Void
*/


typedef struct _HANDLE_TRACE_DB_ENTRY
{
	CLIENT_ID ClientId;
	PVOID Handle;
	UINT32 Type;
	PVOID StackTrace[16];
}HANDLE_TRACE_DB_ENTRY;



typedef struct _HANDLE_TRACE_DEBUG_INFO
{
	INT32 RefCount;
	UINT32 TableSize;
	UINT32 BitMaskFlags;
	FAST_MUTEX CloseCompactionLock;
	UINT32 CurrentStackIndex;
	HANDLE_TRACE_DB_ENTRY TraceDb[1];
} HANDLE_TRACE_DEBUG_INFO, *PHANDLE_TRACE_DEBUG_INFO;
typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		PVOID Object;
		UINT32 ObAttributes;
		struct _HANDLE_TABLE_ENTRY *InfoTable;
		UINT64 Value;
	};
	union
	{
		UINT32 GrantedAccess;
		struct
		{
			USHORT GrantedAccessIndex;
			USHORT CreatorBackTraceIndex;
		};
		INT32 NextFreeTableEntry;
	};
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE
{
	UINT64 TableCode;
	PEPROCESS *QuotaProcess;
	PVOID UniqueProcessId;
	EX_PUSH_LOCK HandleLock;
	LIST_ENTRY HandleTableList;
	EX_PUSH_LOCK HandleContentionEvent;
	PHANDLE_TRACE_DEBUG_INFO DebugInfo;
	INT32 ExtraInfoPages;
	UINT32 Flags;   //Pos 0, 1 Bit
	UINT32 FirstFreeHandle;
	PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
	UINT32 HandleCount;
	UINT32 NextHandleNeedingPool;
	UINT32 HandleCountHighWatermark;
}HANDLE_TABLE, *PHANDLE_TABLE;


typedef struct _PEB_LDR_DATA {
	UINT32	Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	UCHAR ShutdownInProgress;
	PVOID ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	VOID * EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY; 

#endif

#endif