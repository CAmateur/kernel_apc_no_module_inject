#pragma once

#ifndef ENUM_UTILS

#define ENUM_UTILS

#include<ntifs.h>

#include"declare_etc.h"

#include"kernel_mm_load_dll.h"

#include"apc.h"

typedef ULONG64 HMODULE;

typedef PULONG PPEB32;

NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(IN PEPROCESS Process);

NTKERNELAPI
PPEB
NTAPI
PsGetProcessPeb(IN PEPROCESS Process);



#pragma pack(4)
typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

//���Peb�ṹ��ָ��

//EnumProcessModuleByPebx64 ö�ٵ���Peb64���Ldr

//EnumProcessModuleByPebx32 ö�ٵ���Peb32���Ldr

//dllName ģ�������

//hModuleΪdllģ��Ļ���ַ

NTSTATUS EnumProcessModuleByPebx64(IN PPEB pPeb, IN PUNICODE_STRING dllName, OUT HMODULE* hModule);

NTSTATUS EnumProcessModuleByPebx32(IN PPEB32 pPeb32, IN PUNICODE_STRING dllName, OUT HMODULE* hModule);


//dllName

//pKprocessΪdllģ�����ڵĽ��̽ṹ�����ָ��

//hModuleΪdllģ��Ļ���ַ

NTSTATUS EnumEProcess(IN PUNICODE_STRING dllName, OUT PEPROCESS* pKprocess, OUT HMODULE* hModule, IN ULONG mode);

//dllName

//pKprocessΪdllģ�����ڵĽ��̽ṹ�����ָ��

//hModuleΪdllģ��Ļ���ַ

NTSTATUS GetModuleHandlex64(IN PUNICODE_STRING dllName, OUT PEPROCESS* pKprocess, OUT HMODULE* hModule);

NTSTATUS GetModuleHandlex32(IN PUNICODE_STRING dllName, OUT PEPROCESS* pKprocess, OUT HMODULE* hModule);


//tempepΪ���̽ṹ��ָ��

//����ֵ���ɹ������ʺ�APC������߳̽ṹ��ָ�룬���򷵻�NULL

PETHREAD FindThreadInProcess(IN PEPROCESS temPro);


//proNameΪ������

//����ֵ���ɹ������ʺ�APC������߳̽ṹ��ָ�룬���򷵻�NULL

ULONG LookupProcessGetPidByName(IN PCHAR proName);

//pThreadΪɸѡ���߳�ָ��

//����ֵ���������棬pThread������apc��������������ؼ٣�����ϲ���apc���������

BOOLEAN SkipApcThread(IN PETHREAD pThread);



#endif