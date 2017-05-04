#include "util.h"

//

#ifdef WIN32
const int MAX_COUNT_ENTRY = 4096 / 8;
const int MAX_LEVEL2 = 4096 / 4;
#else
const int MAX_COUNT_ENTRY = 4096 / 16;
const int MAX_LEVEL2 = 4096 / 8;
#endif
void *getPspClidTable()
{
	int i = 0;
	UNICODE_STRING	uPsLookProcessByProcessId;
	RtlInitUnicodeString(&uPsLookProcessByProcessId, L"PsLookupProcessByProcessId");
	PVOID pPsLookProcessByProcessId = MmGetSystemRoutineAddress(&uPsLookProcessByProcessId);
	if (!pPsLookProcessByProcessId)
	{
		DbgPrint("MmGetSystemRoutineAddress return null\n");
		return NULL;
	}
#ifdef WIN32
	const int offset_x86=0x18;
#else
	ULONGLONG pPspClidTable = (ULONGLONG)pPsLookProcessByProcessId & 0xFFFFFFFF00000000;
	//偏移0x37是PspCidTable
	//fffff800`0414d784 488b0dddd3edff  mov     rcx,qword ptr [nt!PspCidTable (fffff800`0402ab68)]
	const int offset_x64 = 0x37;
	ULONG offsetValue = *(PULONG)((UCHAR*)(pPsLookProcessByProcessId)+offset_x64);
	//偏移0x3b是下一条指令
	ULONG offsetNextCommand = ((UCHAR*)(pPsLookProcessByProcessId)+0x3b);
	ULONG pspCildTableOffset = offsetValue + offsetNextCommand;
	pPspClidTable += pspCildTableOffset;
	DbgPrint("the offsetValue is %llx", pPspClidTable);
	return pPspClidTable;
#endif // Win64
}


PHANDLE_TABLE*getHandleTable(PVOID pPspClidTable)
{
#ifdef WIN32
#else
	ULONGLONG HandleTable = *(ULONGLONG*)pPspClidTable;
	DbgPrint("handleTable is %llx", HandleTable);
	return HandleTable;
#endif
}


BOOLEAN isProcess(PEPROCESS pEprocess)
{
#ifdef WIN32
#else
	//偏移0x30是_OBJECT_HEADER _OBJECT_HEADER偏移0x18是typeIndex
	UCHAR cTypeIndex = *((UCHAR*)pEprocess - 0x30 + 0x18);
	return cTypeIndex == 0x7 ? TRUE : FALSE;
#endif
}

BOOLEAN isAlive(PEPROCESS pEprocess)
{
#ifdef WIN32
#else
	PLARGE_INTEGER pLi = (PLARGE_INTEGER)((UCHAR*)pEprocess+0x170);
	return pLi->QuadPart == 0 ? TRUE : FALSE;
#endif
}

void travelThreadList(PKPROCESS pKProcess)
{
#ifdef WIN32
#else
	PLIST_ENTRY pListEntry = (PLIST_ENTRY)((UCHAR*)pKProcess + 0x30);
	PLIST_ENTRY pListEntryHeader = pListEntry;
	PLIST_ENTRY pCurrentListEntry = pListEntry->Flink;
	while (pListEntryHeader != pCurrentListEntry)
	{
		PETHREAD pEthread = (PETHREAD)((UCHAR*)pCurrentListEntry - 0x2f8);
		PCLIENT_ID pClientId = (PCLIENT_ID)((UCHAR*)pEthread + 0x3b0);
		DbgPrint("The tid is %llx \n",pClientId->UniqueThread);
		pCurrentListEntry = pCurrentListEntry->Flink;
	}
#endif
}

void treatPspCidTableLevel0(PHANDLE_TABLE_ENTRY pHandleTableEntry)
{
	int i = 0;
	for (; i < MAX_COUNT_ENTRY; i++)
	{
		PEPROCESS pCurrentEprocess = (ULONGLONG)(pHandleTableEntry[i].Object)& ~0x7;
		if (pCurrentEprocess&&MmIsAddressValid(pCurrentEprocess))
		{
#ifdef WIN32
#else
			//必须是存在的进程，否则会发生缺页，BSOD!
			if (isProcess(pCurrentEprocess)&&isAlive(pCurrentEprocess))
			{
				ULONGLONG* pUniqueProcessId = (UCHAR*)pCurrentEprocess + 0x180;
				char *pImageFileName = (UCHAR*)pCurrentEprocess + 0x2e0;
				DbgPrint("The PID is %d ,the ImageFileName is %s \n", *pUniqueProcessId, pImageFileName == 0 ? "NULL" : pImageFileName);
				PRKAPC_STATE state;
				DbgPrint("The current IRQL is %d\n", KeGetCurrentIrql());
				KeStackAttachProcess(pCurrentEprocess, &state);
				PPEB pCurrentPeb = *(ULONGLONG*)((UCHAR*)pCurrentEprocess + 0x338);
				DbgPrint("Current peb is %llx \n", pCurrentPeb);
				if (pCurrentPeb == NULL)
				{
					//System中PEB为NULL 没有用户态模块
					KeUnstackDetachProcess(&state);
					continue;
				}
				PPEB_LDR_DATA pldr = *(ULONGLONG*)(((UCHAR*)pCurrentPeb + 0x18));
				DbgPrint("Current pldr is %llx\n", pldr);
				PLIST_ENTRY pListEntryHeader = &pldr->InLoadOrderModuleList;
				PLIST_ENTRY pListEntryCurrent = pldr->InLoadOrderModuleList.Flink;
				DbgPrint("Current pListEntryCurrent is %llx\n", pListEntryCurrent);
				DbgPrint("Current pListEntryHeader is %llx\n", pListEntryHeader);
				while (pListEntryCurrent != pListEntryHeader)
				{
					PLDR_DATA_TABLE_ENTRY pldrDataTableEntry = pListEntryCurrent;
					if (pldrDataTableEntry->FullDllName.Buffer != NULL)
						DbgPrint("the load is %wZ \n", &pldrDataTableEntry->FullDllName);
					pListEntryCurrent = pListEntryCurrent->Flink;
				}
				KeUnstackDetachProcess(&state);
				travelThreadList(pCurrentEprocess);
				DbgPrint("The current IRQL is %d\n", KeGetCurrentIrql());
			}
#endif
		}
	}
}

void treatPspCidTableLevel1(PHANDLE_TABLE pHandleTable)
{
#ifdef WIN32
#else
	int i = 0;
	ULONGLONG* pHandleTableEntryArray = pHandleTable->TableCode &~0x3;
	//DbgPrint(" pHandleTableEntryArray is %llx", pHandleTableEntryArray);
	UINT32 entrySize = pHandleTable->NextHandleNeedingPool / 4 / MAX_COUNT_ENTRY;
	for (; i < entrySize; i++)
	{
		ULONGLONG level0Addr = (ULONGLONG)pHandleTableEntryArray[i];
		if (!pHandleTableEntryArray[i])
			continue;
		treatPspCidTableLevel0(level0Addr);
	}
#endif
}

void treatPspCidTableLevel2(PHANDLE_TABLE pHandleTable)
{

#ifdef WIN32
#else
	int i = 0;
	ULONGLONG* pHandleTableEntryArray = pHandleTable->TableCode & ~0x3;
	UINT32 entrySize = pHandleTable->NextHandleNeedingPool / 4 / MAX_COUNT_ENTRY / MAX_LEVEL2;
	for (; i < entrySize; i++)
	{
		ULONGLONG levelAddr = (ULONGLONG)pHandleTableEntryArray[i];
		treatPspCidTableLevel1(levelAddr);
	}
#endif

}

void treatPspCildTable(PHANDLE_TABLE pHandleTable)
{
	INT tableLevel = pHandleTable->TableCode & 0x3;
	PVOID pTableAddress = pHandleTable->TableCode&~0x3;
	UINT32 nNextHandleNeedingPool = pHandleTable->NextHandleNeedingPool;
	switch (tableLevel)
	{
	case 0:
		treatPspCidTableLevel0(pHandleTable);
		break;
	case 1:
		treatPspCidTableLevel1(pHandleTable);
		break;
	case 2:
		treatPspCidTableLevel2(pHandleTable);
		break;
	default:
		break;
	}
}

