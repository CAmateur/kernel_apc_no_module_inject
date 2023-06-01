#pragma once

#include"enum_utils.h"

#include"offsets.h"

//pPeb为peb结构体的指针

//dllName

//hModule为dll模块的基地址

NTSTATUS EnumProcessModuleByPebx64(IN PPEB pPeb, IN PUNICODE_STRING dllName, OUT HMODULE* hModule)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PULONG64 pLdr = (PULONG64) * (PULONG64)((ULONG64)pPeb + _1809_Ldr);

	PLIST_ENTRY64 pList = (PLIST_ENTRY64) * (PULONG64)((ULONG64)pLdr + _1809_InLoadOrderModuleList);

	PLIST_ENTRY64 pHead = pList;

	PLIST_ENTRY64 pPoniter = pList;

	PULONG64 pDllBase = NULL;

	PULONG64 pEntryPoint = NULL;

	PULONG64 pFullDllName = NULL;

	PULONG64 pBaseDllName = NULL;

	PULONG64 pFullDllNameBuffer = NULL;

	PULONG64 pBaseDllNameBuffer = NULL;

	do
	{

		pDllBase = (PULONG64) * (PULONG64)((ULONG64)pPoniter + _1809_DllBase);

		if (!pDllBase)
			goto pmEnd;

		pEntryPoint = (PULONG64) * (PULONG64)((ULONG64)pPoniter + _1809_EntryPoint);

		pFullDllName = (PULONG64)((ULONG64)pPoniter + _1809_FullDllName);

		pBaseDllName = (PULONG64)((ULONG64)pPoniter + _1809_BaseDllName);

		if (pFullDllName && pBaseDllName)
		{
			pFullDllNameBuffer = (PULONG64)((PUNICODE_STRING)pFullDllName)->Buffer;
			pBaseDllNameBuffer = (PULONG64)((PUNICODE_STRING)pBaseDllName)->Buffer;

			if (RtlEqualUnicodeString(dllName, (PUNICODE_STRING)pBaseDllName, TRUE))
			{
				*hModule = (HMODULE)pDllBase;

				DbgPrint("找到%ws 模块: %p\n", pBaseDllNameBuffer, pDllBase);

				status = STATUS_SUCCESS;

				return status;
			}
		}

		DbgPrint("DllBase:%p EntryPoint:%p FullDllName:%ws BaseDllName:%ws\n", pDllBase, pEntryPoint, pFullDllNameBuffer, pBaseDllNameBuffer);

	pmEnd:

		pPoniter = (PLIST_ENTRY64)pPoniter->Flink;

	} while (pPoniter != pHead);

	*hModule = NULL;

	return status;
}



NTSTATUS EnumProcessModuleByPebx32(IN PPEB32 pPeb32, IN PUNICODE_STRING dllName, OUT HMODULE* hModule)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PPEB_LDR_DATA32 pLdr = *(PINT32)((ULONG64)pPeb32 + _1809_PEB32Ldr);

	PLIST_ENTRY32 pList = &pLdr->InLoadOrderModuleList;

	PLIST_ENTRY32 pHead = pList;

	PLDR_DATA_TABLE_ENTRY32 pPoniter = pList;

	PULONG64 pDllBase = NULL;


	do
	{

		pDllBase = pPoniter->DllBase;

		if (!pDllBase)
			goto pmEnd;


		UNICODE_STRING temDllName = { 0 };

		RtlInitUnicodeString(&temDllName, pPoniter->BaseDllName.Buffer);

		if (RtlEqualUnicodeString(dllName, &temDllName, TRUE))
		{
			*hModule = pDllBase;

			DbgPrint("找到%ws 模块: %p\n", (PWCHAR)pPoniter->FullDllName.Buffer, pDllBase);

			status = STATUS_SUCCESS;

			return status;
		}


		DbgPrint("DllBase:%p EntryPoint:%p FullDllName:%ws BaseDllName:%ws\n", pDllBase, pPoniter->EntryPoint, (PWCHAR)pPoniter->FullDllName.Buffer, (PWCHAR)pPoniter->BaseDllName.Buffer);

	pmEnd:

		pPoniter = ((PLIST_ENTRY32)pPoniter)->Flink;

	} while (pPoniter != pHead);

	*hModule = NULL;

	return status;
}

//dllName

//pKprocess为dll模块所在的进程结构体二级指针

//hModule为dll模块的基地址

NTSTATUS EnumEProcess(IN PUNICODE_STRING dllName, OUT PEPROCESS* pKprocess, OUT HMODULE* hModule, IN ULONG mode)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	//遍历所有进程

	PEPROCESS pProcess = PsGetCurrentProcess();


	//PLIST_ENTRY64 pList = (ULONG64)pProcess + 0x2e8;
	PLIST_ENTRY64 pList = (ULONG64)pProcess + _1809_ProcessListEntry;

	PLIST_ENTRY64 pHead = pList->Blink;

	PLIST_ENTRY64 pPoniter = pList->Blink;

	KAPC_STATE KPCR = { 0 };

	PEPROCESS pProcessTemp = NULL;

	PPEB pPeb = NULL;

	PPEB32 pPeb32 = NULL;


	do
	{
		pProcessTemp = (PEPROCESS)((ULONG64)pPoniter - _1809_ProcessListEntry);

		//DbgPrint("EPROCESS:%p NAME:%s\n", pProcessTemp, (PCSTR)((ULONG64)pProcessTemp + 0x450));

		status = STATUS_SUCCESS;

		if (mode == 32)
		{
			//pPeb32 = PsGetProcessWow64Process(pProcessTemp);


			//防止蓝屏

			pPeb32 = *(PULONG64)((ULONG64)pProcessTemp + _1809_Wow64Process);


			if (!MmIsAddressValid(pPeb32))
				goto pEnd;
			pPeb32 = *(PULONG64)(pPeb32);

			if (!pPeb32)
				goto pEnd;

			//挂靠才能读PEB
			KeStackAttachProcess(pProcessTemp, &KPCR);

			status = EnumProcessModuleByPebx32(pPeb32, dllName, hModule);

			KeUnstackDetachProcess(&KPCR);

		}
		else
		{

			//遍历进程的模块信息
			pPeb = PsGetProcessPeb(pProcessTemp);

			if (!pPeb)
				goto pEnd;

			//挂靠才能读PEB
			KeStackAttachProcess(pProcessTemp, &KPCR);

			status = EnumProcessModuleByPebx64(pPeb, dllName, hModule);

			KeUnstackDetachProcess(&KPCR);

		}



		if (NT_SUCCESS(status))
		{
			*pKprocess = pProcessTemp;
			break;
		}
	pEnd:

		pPoniter = pPoniter->Blink;

	} while (pPoniter != pHead);

	return status;
}


//proName为进程名

//返回值：成功返回适合APC插入的线程结构体指针，否则返回NULL

ULONG LookupProcessGetPidByName(IN PCHAR proName)
{
	//遍历所有进程

	PEPROCESS pProcess = PsGetCurrentProcess();

	PLIST_ENTRY64 pList = (ULONG64)pProcess + _1809_ProcessListEntry;

	PLIST_ENTRY64 pHead = pList->Blink;

	PLIST_ENTRY64 pPoniter = pList->Blink;

	KAPC_STATE KPCR = { 0 };

	PEPROCESS pProcessTemp = NULL;

	do
	{
		pProcessTemp = (PEPROCESS)((ULONG64)pPoniter - _1809_ProcessListEntry);



		//DbgPrint("EPROCESS:%p NAME:%s\n", pProcessTemp, (PCSTR)((ULONG64)pProcessTemp + 0x450));

		if (!memcmp(proName, (PCSTR)((ULONG64)pProcessTemp + _1809_ImageFileName), strlen(proName)))
		{
			//DbgPrint("Pid:%d NAME:%s\n", *(PULONG64)((ULONG64)pProcessTemp + 0x2e0), (PCSTR)((ULONG64)pProcessTemp + 0x450));

			return  *(PULONG64)((ULONG64)pProcessTemp + _1809_UniqueProcessId);
		}

	pEnd:

		pPoniter = pPoniter->Blink;

	} while (pPoniter != pHead);

	return NULL;


}

//dllName

//pKprocess为dll模块所在的进程结构体二级指针

//hModule为dll模块的基地址

NTSTATUS GetModuleHandlex64(IN PUNICODE_STRING dllName, OUT PEPROCESS* pKprocess, OUT HMODULE* hModule)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	status = EnumEProcess(dllName, pKprocess, hModule, 64);

	return status;
}

NTSTATUS GetModuleHandlex32(IN PUNICODE_STRING dllName, OUT PEPROCESS* pKprocess, OUT HMODULE* hModule)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	status = EnumEProcess(dllName, pKprocess, hModule, 32);

	return status;
}

//tempep为进程结构体指针

//返回值：成功返回适合APC插入的线程结构体指针，否则返回NULL

PETHREAD FindThreadInProcess(IN PEPROCESS temPro)
{
	PETHREAD pRetThreadObj = NULL, pTempThreadObj = NULL;

	PLIST_ENTRY pListHead = NULL;

	PLIST_ENTRY pListFink = NULL;



	pListHead = (PLIST_ENTRY)((PUCHAR)temPro + _1809_ThreadListHead);

	pListFink = pListHead->Flink;

	for (pListFink; pListFink != pListHead; pListFink = pListFink->Flink)
	{
		pTempThreadObj = (PETHREAD)((PUCHAR)pListFink - _1809_ThreadListEntryGap);

		if (!MmIsAddressValid(pTempThreadObj))
			continue;

		if (!SkipApcThread(pTempThreadObj))
		{
			pRetThreadObj = pTempThreadObj;

			break;
		}
	}

	return pRetThreadObj;
}



//pThread为筛选的线程指针

//返回值：若返回真，pThread不符合apc插入的条件，返回假，则符合插入apc插入的条件

BOOLEAN SkipApcThread(IN PETHREAD pThread)
{
	PUCHAR pTeb64 = NULL;

	pTeb64 = (PUCHAR)PsGetThreadTeb(pThread);

	if (!pTeb64)
		return TRUE;

	//Win32ThreadInfo
	if (*(PULONG64)(pTeb64 + _1809_Win32ThreadInfo) != 0)
		return TRUE;

	////ActivationContextStackPointer
	//if (*(PULONG64)(pTeb64 + _1809_ActivationContextStackPointer) != 0)
	//	return TRUE;

	////ThreadLocalStoragePointer
	//if (*(PULONG64)(pTeb64 + _1809_ThreadLocalStoragePointer) != 0)
	//	return TRUE;

	return FALSE;

}