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

//获得Peb结构体指针

//EnumProcessModuleByPebx64 枚举的是Peb64里的Ldr

//EnumProcessModuleByPebx32 枚举的是Peb32里的Ldr

//dllName 模块的名字

//hModule为dll模块的基地址

NTSTATUS EnumProcessModuleByPebx64(IN PPEB pPeb, IN PUNICODE_STRING dllName, OUT HMODULE* hModule);

NTSTATUS EnumProcessModuleByPebx32(IN PPEB32 pPeb32, IN PUNICODE_STRING dllName, OUT HMODULE* hModule);


//dllName

//pKprocess为dll模块所在的进程结构体二级指针

//hModule为dll模块的基地址

NTSTATUS EnumEProcess(IN PUNICODE_STRING dllName, OUT PEPROCESS* pKprocess, OUT HMODULE* hModule, IN ULONG mode);

//dllName

//pKprocess为dll模块所在的进程结构体二级指针

//hModule为dll模块的基地址

NTSTATUS GetModuleHandlex64(IN PUNICODE_STRING dllName, OUT PEPROCESS* pKprocess, OUT HMODULE* hModule);

NTSTATUS GetModuleHandlex32(IN PUNICODE_STRING dllName, OUT PEPROCESS* pKprocess, OUT HMODULE* hModule);


//tempep为进程结构体指针

//返回值：成功返回适合APC插入的线程结构体指针，否则返回NULL

PETHREAD FindThreadInProcess(IN PEPROCESS temPro);


//proName为进程名

//返回值：成功返回适合APC插入的线程结构体指针，否则返回NULL

ULONG LookupProcessGetPidByName(IN PCHAR proName);

//pThread为筛选的线程指针

//返回值：若返回真，pThread不符合apc插入的条件，返回假，则符合插入apc插入的条件

BOOLEAN SkipApcThread(IN PETHREAD pThread);



#endif