#pragma once

#ifndef X64APC

#define X64APC

#include<ntifs.h>

#include"pe.h"

#include"enum_utils.h"

#include"kernel_mm_load_dll.h"

#include"global_vars.h"


typedef VOID(NTAPI* PKNORMAL_ROUTINE)(

	PVOID NormalContext,

	PVOID SystemArgument1,

	PVOID SystemArgument2
	);

typedef VOID(NTAPI* PKKERNEL_ROUTINE)(

	PKAPC Apc,

	PKNORMAL_ROUTINE* NormakRoutine,

	PVOID* NormalContext,

	PVOID* SystemArgument1,

	PVOID* SystemArgument2
	);

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(PRKAPC Apc);

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,

	AttachedApcEnvironment,

	CurrentApcEnvironment,

	InsertApcEnvironment

} KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;





NTKERNELAPI

VOID

NTAPI

KeInitializeApc(

	IN PKAPC Apc,

	IN PKTHREAD Thread,

	IN KAPC_ENVIRONMENT Environment,

	IN PKKERNEL_ROUTINE KernelRoutine,

	IN PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL,

	IN PKNORMAL_ROUTINE NormalRoutine OPTIONAL,

	IN KPROCESSOR_MODE ApcMode OPTIONAL,

	IN PVOID NormalContext OPTIONAL
);





NTKERNELAPI

BOOLEAN

NTAPI

KeInsertQueueApc(

	IN PKAPC Apc,

	IN PVOID SystemArgument1,

	IN PVOID SystemArgument2,

	IN KPRIORITY Increment
);




NTKERNELAPI

PVOID

NTAPI

PsGetThreadTeb(

	IN PETHREAD pThread);






typedef NTSTATUS(NTAPI* fn_NtCreateThreadEx)
(
	OUT PHANDLE ThreadHandle,

	IN ACCESS_MASK DesiredAccess,

	IN PVOID ObjectAttributes,

	IN HANDLE ProcessHandle,

	IN PVOID lpStartAddress,

	IN PVOID lpParameter,

	IN ULONG CreateThreadFlags,

	IN SIZE_T ZeroBits,

	IN SIZE_T StackSize,

	IN SIZE_T MaximunStackSize,

	IN PVOID pUnkown
	);


NTKERNELAPI

BOOLEAN

NTAPI

KeTestAlertThread(IN  KPROCESSOR_MODE AlertMode);




NTSTATUS KernelQueueUserApc(

	IN PETHREAD pthreadobj,

	IN PVOID puserapccall,

	IN PVOID apccontext,

	IN 	PVOID arg2,

	IN PVOID arg3,

	IN BOOLEAN bforce
);


VOID KernelAlertThreadApc(

	IN PKAPC Apc,

	IN PKNORMAL_ROUTINE* NormalRoutine,

	IN PVOID* NormalContext,

	IN PVOID* SystemArgument1,

	IN PVOID* SystemArgument2
);




VOID KernelInjectApc(

	IN PKAPC Apc,

	IN PKNORMAL_ROUTINE* NormalRoutine,

	IN PVOID* NormalContext,

	IN PVOID* SystemArgument1,

	IN PVOID* SystemArgument2
);



VOID KernelApcNormalRoutine(PVOID normalContext, PVOID arg1, PVOID arg2);


NTSTATUS KernelApcMapInjectCore(IN ULONG pid, IN  PVOID fildBuffer, IN  SIZE_T fileSize, IN  ULONG mode);

NTSTATUS KernelApcMapInjectx64(IN PCHAR proceessName, IN  PCHAR dllPath);

NTSTATUS KernelApcMapInjectx32(IN PCHAR proceessName, IN  PCHAR dllPath);

NTSTATUS KernelApcMapInject(IN PCHAR proceessName, IN  PCHAR dllPath, IN ULONG mode);

#endif // X64APC
