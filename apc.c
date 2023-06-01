#pragma once

#include"apc.h"

#include"offsets.h"

#include"file_utils.h"




VOID KernelAlertThreadApc(IN PKAPC Apc, IN PKNORMAL_ROUTINE* NormalRoutine, IN  PVOID* NormalContext, IN  PVOID* SystemArgument1, IN PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	//唤醒线程

	KeTestAlertThread(UserMode);

	DbgPrint("KernelRoutine irql:%d\n", KeGetCurrentIrql());

	ExFreePool(Apc);

	return;


}

VOID KernelApcNormalRoutine(IN PVOID normalContext, IN PVOID arg1, IN PVOID arg2)
{
	DbgPrint("NormalRoutineIrql:%d\n", KeGetCurrentIrql());

	return;
}


NTSTATUS KernelApcMapInjectCore(IN  ULONG pid, IN PVOID fildBuffer, IN  SIZE_T fileSize, IN  ULONG mode)
{
	NTSTATUS  status = STATUS_UNSUCCESSFUL;

	PEPROCESS  temPro = NULL;

	KAPC_STATE kApcs = { 0 };

	BOOLEAN  attached = FALSE;

	PETHREAD apcThreadObj = NULL;

	PVOID  pR3ImageBuffer = NULL;

	LARGE_INTEGER sleepTime = { 0 };

	PVOID dllMainBase = NULL;

	do
	{

		status = PsLookupProcessByProcessId((HANDLE)pid, &temPro);

		if (!NT_SUCCESS(status))
			break;

		KeStackAttachProcess(temPro, &kApcs);

		attached = TRUE;

		apcThreadObj = FindThreadInProcess(PsGetCurrentProcess());

		if (apcThreadObj == NULL)
		{
			DbgPrint("thread not found\n");
			break;
		}

		ObReferenceObject(apcThreadObj);

		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pR3ImageBuffer, 0, &fileSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!NT_SUCCESS(status))
			break;

		RtlZeroMemory(pR3ImageBuffer, fileSize);



		if (mode == 32)
		{
			if (!MmPEtoMemImagePex32(fildBuffer, pR3ImageBuffer))
				break;

			

			dllMainBase = GetDllMainBasex32(pR3ImageBuffer);

			if (dllMainBase == NULL)
				break;

			//得到PE文件拉伸后的入口

			dllMainBase = (~(ULONG64)dllMainBase + 1) << 2;

		}
		else
		{

			if (!MmPEtoMemImagePex64(fildBuffer, pR3ImageBuffer))
				break;


			//得到PE文件拉伸后的入口

			dllMainBase = GetDllMainBasex64(pR3ImageBuffer);

			if (dllMainBase == NULL)
				break;

		}

		//擦除PE信息

		MmErasePeInfo(pR3ImageBuffer);

		//初始化事件

		//代码中KeInitializeEvent中使用了SynchronizationEvent，导致这个事件成为所谓的“自动重设”事件。

		//一个事件如果被设置，那么所有KeWaitForSingleObject等待这个事件的地方都会通过。如果要继续重复使用这个事件，必须重设这个事件。

		//当KeInitializeEvent第二个参数设置为NotificationEvent时，这个事件必须要手动重设才能使用。

		KeInitializeEvent(&globalVars.apcEnvent, SynchronizationEvent, FALSE);

		sleepTime.QuadPart = -10000000 * 5;

		status = KernelQueueUserApc(apcThreadObj, dllMainBase, pR3ImageBuffer, DLL_PROCESS_ATTACH, NULL, TRUE);

		//事件初始化之后就可以使用了，在一个函数中，我们可以等待某个事件

		//如果这个事件没有被人设置，那就会阻塞在这里继续等待

		KeWaitForSingleObject(&globalVars.apcEnvent, Executive, KernelMode, FALSE, &sleepTime);

		status = STATUS_SUCCESS;

		break;


	} while (1);


	if (attached)
	{
		if (!globalVars.acpInsert)
		{

			status = STATUS_UNSUCCESSFUL;

		}
		else
		{
			sleepTime.QuadPart = -10000000 * 3;

			KeDelayExecutionThread(KernelMode, 0, &sleepTime);

		}

		if (apcThreadObj)
		{

			ObDereferenceObject(apcThreadObj);

		}

		KeUnstackDetachProcess(&kApcs);
	}

	return status;




}



NTSTATUS KernelQueueUserApc(IN PETHREAD pThreadobj, IN PVOID pUserApcCall, IN PVOID apcContext, IN  PVOID arg2, IN  PVOID arg3, IN  BOOLEAN force)
{

	PKAPC pForceApc = NULL;

	PKAPC pInjectApc = NULL;

	if (pThreadobj == NULL)
		return STATUS_INVALID_PARAMETER;


	pInjectApc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));

	RtlZeroMemory(pInjectApc, sizeof(KAPC));


	KeInitializeApc(
		pInjectApc,
		(PKTHREAD)pThreadobj,
		OriginalApcEnvironment,
		(PKKERNEL_ROUTINE)KernelInjectApc,
		NULL,
		(PKNORMAL_ROUTINE)pUserApcCall,
		UserMode,
		apcContext);

	//再准备一个APC 万一线程在休眠，就用这个APC尝试去唤醒
	if (force)
	{
		pForceApc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));

		RtlZeroMemory(pForceApc, sizeof(KAPC));

		KeInitializeApc(

			pForceApc,

			(PKTHREAD)pThreadobj,

			OriginalApcEnvironment,

			(PKKERNEL_ROUTINE)KernelAlertThreadApc,

			NULL,

			KernelApcNormalRoutine,

			KernelMode,

			NULL);

	}

	//插入注入APC

	if (KeInsertQueueApc(pInjectApc, arg2, arg3, 0))
	{
		if (force && pForceApc)
		{
			//插入唤醒APC
			KeInsertQueueApc(pForceApc, NULL, NULL, 0);
		}

		return STATUS_SUCCESS;
	}
	else
	{
		if (pInjectApc)
			ExFreePool(pInjectApc);

		if (pForceApc)
			ExFreePool(pForceApc);

		return STATUS_NOT_CAPABLE;

	}

	return STATUS_SUCCESS;

}


VOID KernelInjectApc(IN PKAPC Apc, IN PKNORMAL_ROUTINE* NormalRoutine, IN PVOID* NormalContext, IN PVOID* SystemArgument1, IN  PVOID* SystemArgument2)
{

	UNREFERENCED_PARAMETER(SystemArgument1);

	UNREFERENCED_PARAMETER(SystemArgument2);

	// 这里判断一下线程挂了没 如果挂了 就对NormalRoutine 清零 免得R3的APC执行

	if (PsIsThreadTerminating(PsGetCurrentThread()))
		*NormalRoutine = NULL;

	ExFreePool(Apc);

	globalVars.acpInsert = TRUE;

	KeSetEvent(&globalVars.apcEnvent, 0, FALSE);

	return;
}



NTSTATUS KernelApcMapInjectx64(IN PCHAR proceessName, IN  PCHAR dllPath)
{
	return KernelApcMapInject(proceessName, dllPath, 64);

}

NTSTATUS KernelApcMapInjectx32(IN PCHAR proceessName, IN  PCHAR dllPath)
{
	return KernelApcMapInject(proceessName, dllPath, 32);
}


NTSTATUS KernelApcMapInject(IN PCHAR proceessName, IN PCHAR dllPath, IN  ULONG mode)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ULONG pid = 0;

	SIZE_T dwSizeOfImage = 0;

	//遍历的结构体中，processName的大小的为15个字符，因此这样填

	pid = LookupProcessGetPidByName(proceessName);

	if (pid)
	{

		//读取原PE文件到缓存区

		status = GetPeFileToBuffer(dllPath, &globalVars.peBuffer);

		if (!NT_SUCCESS(status))
			return STATUS_UNSUCCESSFUL;

		if (mode == 32)
		{

			dwSizeOfImage = GetSizeOfImagex32(globalVars.peBuffer);

			if (globalVars.peBuffer)
				return KernelApcMapInjectCore(pid, globalVars.peBuffer, dwSizeOfImage, 32);
		}
		else
		{
			dwSizeOfImage = GetSizeOfImagex64(globalVars.peBuffer);

			if (globalVars.peBuffer)
				return KernelApcMapInjectCore(pid, globalVars.peBuffer, dwSizeOfImage, 64);

		}


	}

	return status;
}



