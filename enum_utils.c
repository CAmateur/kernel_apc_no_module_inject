#pragma once

#include"enum_utils.h"

#include"offsets.h"

//pPebΪpeb�ṹ���ָ��

//dllName

//hModuleΪdllģ��Ļ���ַ

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

				DbgPrint("�ҵ�%ws ģ��: %p\n", pBaseDllNameBuffer, pDllBase);

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

			DbgPrint("�ҵ�%ws ģ��: %p\n", (PWCHAR)pPoniter->FullDllName.Buffer, pDllBase);

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

//pKprocessΪdllģ�����ڵĽ��̽ṹ�����ָ��

//hModuleΪdllģ��Ļ���ַ

NTSTATUS EnumEProcess(IN PUNICODE_STRING dllName, OUT PEPROCESS* pKprocess, OUT HMODULE* hModule, IN ULONG mode)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	//�������н���

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


			//��ֹ����

			pPeb32 = *(PULONG64)((ULONG64)pProcessTemp + _1809_Wow64Process);


			if (!MmIsAddressValid(pPeb32))
				goto pEnd;
			pPeb32 = *(PULONG64)(pPeb32);

			if (!pPeb32)
				goto pEnd;

			//�ҿ����ܶ�PEB
			KeStackAttachProcess(pProcessTemp, &KPCR);

			status = EnumProcessModuleByPebx32(pPeb32, dllName, hModule);

			KeUnstackDetachProcess(&KPCR);

		}
		else
		{

			//�������̵�ģ����Ϣ
			pPeb = PsGetProcessPeb(pProcessTemp);

			if (!pPeb)
				goto pEnd;

			//�ҿ����ܶ�PEB
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


//proNameΪ������

//����ֵ���ɹ������ʺ�APC������߳̽ṹ��ָ�룬���򷵻�NULL

ULONG LookupProcessGetPidByName(IN PCHAR proName)
{
	//�������н���

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

//pKprocessΪdllģ�����ڵĽ��̽ṹ�����ָ��

//hModuleΪdllģ��Ļ���ַ

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

//tempepΪ���̽ṹ��ָ��

//����ֵ���ɹ������ʺ�APC������߳̽ṹ��ָ�룬���򷵻�NULL

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



//pThreadΪɸѡ���߳�ָ��

//����ֵ���������棬pThread������apc��������������ؼ٣�����ϲ���apc���������

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