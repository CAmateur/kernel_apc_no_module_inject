#pragma once
#ifndef _MM_LOAD_DLL_H_

#define _MM_LOAD_DLL_H_

#include<ntifs.h>

#include"pe.h"

#include"enum_utils.h"

typedef ULONG64 HMODULE;

// ģ��LoadLibrary�����ڴ�DLL�ļ���������

// lpData: �ڴ���δ�����PE�ļ������ڴ��ַ

// pBufferMemImagePe: ���������PE�ļ������ڴ��ַ

// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE

BOOL MmPEtoMemImagePex64(IN PVOID lpData, IN PVOID pBufferMemImagePe);

BOOL MmPEtoMemImagePex32(IN PVOID lpData, IN PVOID pBufferMemImagePe);

// ����PE�ṹ,��ȡPE�ļ����ص��ڴ��ľ����С

// lpData: �ڴ���δ�����PE�ļ������ڴ��ַ

// ����ֵ: ����PE�ļ��ṹ��IMAGE_NT_HEADERS.OptionalHeader.SizeOfImageֵ�Ĵ�С

ULONG GetSizeOfImagex64(IN PVOID lpData);

ULONG GetSizeOfImagex32(IN PVOID lpData);



// ��δ�����PE�ڴ����ݰ�SectionAlignment��С����ӳ�䵽lpBaseAddressָ����ڴ���

// lpData: �ڴ�DLL�ļ����ݵĻ�ַ

// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ

// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE

BOOL MmMapFilex64(IN PVOID lpData, IN PVOID lpBaseAddress);

BOOL MmMapFilex32(IN PVOID lpData, IN PVOID lpBaseAddress);



// �޸�PE�ļ��ض�λ����Ϣ

// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ

// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE

BOOL DoRelocationTablex64(IN PVOID lpBaseAddress);

BOOL DoRelocationTablex32(IN PVOID lpBaseAddress);

// ��дPE�ļ��������Ϣ

// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ

// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE

BOOL DoImportTablex64(IN PVOID lpBaseAddress);

BOOL DoImportTablex32(IN PVOID lpBaseAddress);

// �޸�PE�ļ����ػ�ַIMAGE_NT_HEADERS.OptionalHeader.ImageBase

// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE

BOOL SetImageBasex64(IN PVOID lpBaseAddress);

BOOL SetImageBasex32(IN PVOID lpBaseAddress);




// �õ�DLL����ں���DllMain,������ַ��ΪPE�ļ�����ڵ�IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint

// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ

// ����ֵ: �ɹ�������ڵ��ַ��ʧ�ܷ���NULL

PVOID GetDllMainBasex64(IN PVOID lpBaseAddress);

PVOID GetDllMainBasex32(IN PVOID lpBaseAddress);


// ģ��GetProcAddress��ȡ�ڴ�DLL�ĵ�������

// lpBaseAddress: �ڴ�DLL�ļ����ص������еļ��ػ�ַ

// lpszFuncName: ��������������

// ����ֵ: ���ص��������ĵĵ�ַ

PVOID MmGetProcAddressx64(IN HMODULE lpBaseAddress, IN PCHAR lpszFuncName);

PVOID MmGetProcAddressx32(IN HMODULE lpBaseAddress, IN PCHAR lpszFuncName);

BOOL MmErasePeInfo(IN PVOID lpBaseAddress);


#endif
