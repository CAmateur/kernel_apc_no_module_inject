#pragma once

#include"kernel_mm_load_dll.h"



// ģ��LoadLibrary�����ڴ�DLL�ļ���������

// lpData: �ڴ�DLL�ļ����ݵĻ�ַ

// dwSize: �ڴ�DLL�ļ�����չ����Ĵ�С

// ����ֵ: �ڴ�DLL���ص����̵ļ��ػ�ַ

BOOL MmPEtoMemImagePex64(IN PVOID lpData, IN PVOID pBufferMemImagePe)
{

	PVOID lpBaseAddress = pBufferMemImagePe;

	// ��ȡ�����С

	ULONG dwSizeOfImage = GetSizeOfImagex64(lpData);


	if (NULL == lpBaseAddress)
	{

		DbgPrint("ppBufferMemImagePe is NULL!\n");

		return FALSE;

	}

	// ���ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ���

	if (FALSE == MmMapFilex64(lpData, lpBaseAddress))
	{

		DbgPrint("MmMapFile Failed!\n");

		return FALSE;

	}

	// �޸�PE�ļ��ض�λ����Ϣ

	if (FALSE == DoRelocationTablex64(lpBaseAddress))
	{
		DbgPrint("DoRelocationTable Failed!\n");

		return FALSE;

	}


	// ��дPE�ļ��������Ϣ

	if (FALSE == DoImportTablex64(lpBaseAddress))
	{

		DbgPrint("DoImportTable  Failed!\n");

		return FALSE;

	}


	//���������PE��ImageBase

	if (FALSE == SetImageBasex64(lpBaseAddress))
	{

		DbgPrint("SetImageBase  Failed!\n");

		return FALSE;
	}

	return TRUE;
}



BOOL MmPEtoMemImagePex32(IN PVOID lpData, IN PVOID pBufferMemImagePe)
{
	PVOID lpBaseAddress = pBufferMemImagePe;

	// ��ȡ�����С

	ULONG dwSizeOfImage = GetSizeOfImagex32(lpData);

	if (NULL == lpBaseAddress)
	{

		DbgPrint("ppBufferMemImagePe is NULL!\n");

		return FALSE;

	}

	// ���ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ���

	if (FALSE == MmMapFilex32(lpData, lpBaseAddress))
	{

		DbgPrint("MmMapFile Failed!\n");

		return FALSE;

	}

	// �޸�PE�ļ��ض�λ����Ϣ

	if (FALSE == DoRelocationTablex32(lpBaseAddress))
	{
		DbgPrint("DoRelocationTable Failed!\n");

		return FALSE;

	}

	// ��дPE�ļ��������Ϣ

	if (FALSE == DoImportTablex32(lpBaseAddress))
	{
		DbgPrint("DoImportTable  Failed!\n");

		return FALSE;

	}

	//���������PE��ImageBase

	if (FALSE == SetImageBasex32(lpBaseAddress))
	{

		DbgPrint("SetImageBase  Failed!\n");

		return FALSE;
	}

	return TRUE;
}

// ����PE�ṹ,��ȡPE�ļ����ص��ڴ��ľ����С

// lpData: �ڴ�DLL�ļ����ݵĻ�ַ

// ����ֵ: ����PE�ļ��ṹ��IMAGE_NT_HEADERS.OptionalHeader.SizeOfImageֵ�Ĵ�С

ULONG GetSizeOfImagex64(IN PVOID lpData)
{

	ULONG dwSizeOfImage = 0;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpData;

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	dwSizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;

	return dwSizeOfImage;

}


ULONG GetSizeOfImagex32(IN PVOID lpData)
{

	ULONG dwSizeOfImage = 0;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpData;

	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	dwSizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;

	return dwSizeOfImage;

}


// ���ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ���

// lpData: �ڴ�DLL�ļ����ݵĻ�ַ

// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ

// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE

BOOL MmMapFilex64(IN PVOID lpData, IN PVOID lpBaseAddress)
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpData;

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	// ��ȡSizeOfHeaders��ֵ: ����ͷ+�ڱ�ͷ�Ĵ�С

	ULONG dwSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;

	// ��ȡ�ڱ������

	USHORT wNumberOfSections = pNtHeaders->FileHeader.NumberOfSections;

	// ��ȡ��һ���ڱ�ͷ�ĵ�ַ

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG64)pNtHeaders + sizeof(IMAGE_NT_HEADERS64));

	// ���� ����ͷ+�ڱ�ͷ�Ĵ�С

	RtlCopyMemory(lpBaseAddress, lpData, dwSizeOfHeaders);

	// ����SectionAlignmentѭ�����ؽڱ�

	USHORT i = 0;

	PVOID lpSrcMem = NULL;

	PVOID lpDestMem = NULL;

	ULONG dwSizeOfRawData = 0;

	for (i = 0; i < wNumberOfSections; i++)
	{

		if ((0 == pSectionHeader->VirtualAddress) ||

			(0 == pSectionHeader->SizeOfRawData))

		{

			pSectionHeader++;

			continue;

		}

		lpSrcMem = (PVOID)((ULONG64)lpData + pSectionHeader->PointerToRawData);

		lpDestMem = (PVOID)((ULONG64)lpBaseAddress + pSectionHeader->VirtualAddress);

		dwSizeOfRawData = pSectionHeader->SizeOfRawData;

		RtlCopyMemory(lpDestMem, lpSrcMem, dwSizeOfRawData);

		pSectionHeader++;

	}

	return TRUE;

}


BOOL MmMapFilex32(IN PVOID lpData, IN PVOID lpBaseAddress)
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpData;

	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	// ��ȡSizeOfHeaders��ֵ: ����ͷ+�ڱ�ͷ�Ĵ�С

	ULONG dwSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;

	// ��ȡ�ڱ������

	USHORT wNumberOfSections = pNtHeaders->FileHeader.NumberOfSections;

	// ��ȡ��һ���ڱ�ͷ�ĵ�ַ

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG64)pNtHeaders + sizeof(IMAGE_NT_HEADERS32));

	// ���� ����ͷ+�ڱ�ͷ�Ĵ�С

	RtlCopyMemory(lpBaseAddress, lpData, dwSizeOfHeaders);

	// ����SectionAlignmentѭ�����ؽڱ�

	USHORT i = 0;

	PVOID lpSrcMem = NULL;

	PVOID lpDestMem = NULL;

	ULONG dwSizeOfRawData = 0;

	for (i = 0; i < wNumberOfSections; i++)
	{

		if ((0 == pSectionHeader->VirtualAddress) ||

			(0 == pSectionHeader->SizeOfRawData))

		{

			pSectionHeader++;

			continue;

		}

		lpSrcMem = (PVOID)((ULONG64)lpData + pSectionHeader->PointerToRawData);

		lpDestMem = (PVOID)((ULONG64)lpBaseAddress + pSectionHeader->VirtualAddress);

		dwSizeOfRawData = pSectionHeader->SizeOfRawData;

		RtlCopyMemory(lpDestMem, lpSrcMem, dwSizeOfRawData);

		pSectionHeader++;

	}

	return TRUE;

}

// �޸�PE�ļ��ض�λ����Ϣ

// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ

// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE

BOOL DoRelocationTablex64(IN PVOID lpBaseAddress)
{

	/* �ض�λ��Ľṹ��

		//https://blog.csdn.net/m0_67316550/article/details/123472157

	*/


	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((unsigned long long)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);



	// �ж��Ƿ��� �ض�λ��

	if ((PVOID)pLoc == (PVOID)pDosHeader && pLoc->SizeOfBlock == NULL)

	{

		// �ض�λ�� Ϊ��

		return TRUE;

	}



	while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //��ʼɨ���ض�λ��

	{

		USHORT* pLocData = (USHORT*)((PUCHAR)pLoc + sizeof(IMAGE_BASE_RELOCATION));

		//���㱾����Ҫ�������ض�λ���ַ������Ŀ

		int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);



		for (int i = 0; i < nNumberOfReloc; i++)

		{

			// ÿ��WORD����������ɡ���4λָ�����ض�λ�����ͣ�WINNT.H�е�һϵ��IMAGE_REL_BASED_xxx�������ض�λ���͵�ȡֵ��

			// ��12λ�������VirtualAddress���ƫ�ƣ�ָ���˱�������ض�λ��λ�á�


			//��64λϵͳ�У����ֵΪ0x0000A000
			if ((ULONG)(pLocData[i] & 0x0000F000) == 0x0000A000) //����һ����Ҫ�����ĵ�ַ

			{

				// 32λdll�ض�λ��IMAGE_REL_BASED_HIGHLOW

				// ����x86�Ŀ�ִ���ļ������еĻ�ַ�ض�λ����IMAGE_REL_BASED_HIGHLOW���͵ġ�



				ULONG64* pAddress = (ULONG64*)((PUCHAR)pDosHeader + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));

				ULONG64 dwDelta = (ULONG64)pDosHeader - pNtHeaders->OptionalHeader.ImageBase;

				*pAddress += dwDelta;

			}

		}

		//ת�Ƶ���һ���ڽ��д���

		pLoc = (PIMAGE_BASE_RELOCATION)((PUCHAR)pLoc + pLoc->SizeOfBlock);

	}



	return TRUE;

}

BOOL DoRelocationTablex32(IN PVOID lpBaseAddress)
{

	/* �ض�λ��Ľṹ��

		//https://blog.csdn.net/m0_67316550/article/details/123472157

	*/


	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((ULONG64)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);



	// �ж��Ƿ��� �ض�λ��

	if ((PVOID)pLoc == (PVOID)pDosHeader && pLoc->SizeOfBlock == NULL)

	{

		// �ض�λ�� Ϊ��

		return TRUE;

	}



	while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //��ʼɨ���ض�λ��

	{

		USHORT* pLocData = (USHORT*)((PUCHAR)pLoc + sizeof(IMAGE_BASE_RELOCATION));

		//���㱾����Ҫ�������ض�λ���ַ������Ŀ

		int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);



		for (int i = 0; i < nNumberOfReloc; i++)

		{

			// ÿ��WORD����������ɡ���4λָ�����ض�λ�����ͣ�WINNT.H�е�һϵ��IMAGE_REL_BASED_xxx�������ض�λ���͵�ȡֵ��

			// ��12λ�������VirtualAddress���ƫ�ƣ�ָ���˱�������ض�λ��λ�á�


			//��64λϵͳ�У����ֵΪ0x0000A000
			if ((ULONG)(pLocData[i] & 0x0000F000) == 0x00003000) //����һ����Ҫ�����ĵ�ַ

			{

				// 32λdll�ض�λ��IMAGE_REL_BASED_HIGHLOW

				// ����x86�Ŀ�ִ���ļ������еĻ�ַ�ض�λ����IMAGE_REL_BASED_HIGHLOW���͵ġ�



				ULONG64* pAddress = (ULONG64*)((PUCHAR)pDosHeader + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));

				ULONG64 dwDelta = (ULONG64)pDosHeader - pNtHeaders->OptionalHeader.ImageBase;

				*pAddress += dwDelta;

			}

		}

		//ת�Ƶ���һ���ڽ��д���

		pLoc = (PIMAGE_BASE_RELOCATION)((PUCHAR)pLoc + pLoc->SizeOfBlock);

	}



	return TRUE;

}



// ��дPE�ļ��������Ϣ

// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ
// https://blog.csdn.net/xuandao_ahfengren/article/details/112272745
// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE

BOOL DoImportTablex64(IN PVOID lpBaseAddress)
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG64)pDosHeader +

		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


	// ѭ������DLL������е�DLL����ȡ������еĺ�����ַ

	PCHAR lpDllName = NULL;

	HMODULE hDll = NULL;

	PIMAGE_THUNK_DATA64 lpImportNameArray = NULL;

	PIMAGE_IMPORT_BY_NAME lpImportByName = NULL;

	PIMAGE_THUNK_DATA64 lpImportFuncAddrArray = NULL;

	ULONG64 lpFuncAddress = NULL;

	ULONG i = 0;

	CHAR lpImportByName_Name[100];



	while (TRUE)
	{
		if (0 == pImportTable->OriginalFirstThunk)
		{
			break;
		}

		// ��ȡ�������DLL�����Ʋ�����DLL

		lpDllName = (PCHAR)((ULONG64)pDosHeader + pImportTable->Name);

		UNICODE_STRING ustr = { 0 };

		STRING strtemp = { 0 };

		RtlInitString(&strtemp, lpDllName);

		RtlAnsiStringToUnicodeString(&ustr, &strtemp, TRUE);

		PEPROCESS pEprocess = NULL;

		KAPC_STATE KPCR = { 0 };

		GetModuleHandlex64(&ustr, &pEprocess, &hDll);

		RtlFreeUnicodeString(&ustr);

		if (NULL == hDll)
		{
			pImportTable++;

			continue;

		}

		i = 0;

		// ��ȡOriginalFirstThunk�Լ���Ӧ�ĵ��뺯�����Ʊ��׵�ַ

		lpImportNameArray = (PIMAGE_THUNK_DATA64)((ULONG64)pDosHeader + pImportTable->OriginalFirstThunk);

		// ��ȡFirstThunk�Լ���Ӧ�ĵ��뺯����ַ���׵�ַ

		lpImportFuncAddrArray = (PIMAGE_THUNK_DATA64)((ULONG64)pDosHeader + pImportTable->FirstThunk);

		while (TRUE)
		{

			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{

				break;

			}

			// ��ȡIMAGE_IMPORT_BY_NAME�ṹ

			lpImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG64)pDosHeader + lpImportNameArray[i].u1.AddressOfData);

			memset(lpImportByName_Name, 0, sizeof(char) * 100);

			memcpy(lpImportByName_Name, lpImportByName->Name, strlen(lpImportByName->Name));


			// �жϵ�����������ŵ������Ǻ������Ƶ���

			if (IMAGE_ORDINAL_FLAG64 & lpImportNameArray[i].u1.Ordinal)
			{

				// ��ŵ���

				// ��IMAGE_THUNK_DATAֵ�����λΪ1ʱ����ʾ��������ŷ�ʽ���룬��ʱ����λ��������һ���������
				KeStackAttachProcess(pEprocess, &KPCR);

				lpFuncAddress = MmGetProcAddressx64(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));

				KeUnstackDetachProcess(&KPCR);
			}
			else
			{

				// ���Ƶ���
				KeStackAttachProcess(pEprocess, &KPCR);

				lpFuncAddress = MmGetProcAddressx64(hDll, (LPCSTR)lpImportByName_Name);

				KeUnstackDetachProcess(&KPCR);
			}

			// ע��˴��ĺ�����ַ��ĸ�ֵ��Ҫ����PE��ʽ����װ�أ���Ҫ�����ˣ�����

			lpImportFuncAddrArray[i].u1.Function = (ULONG64)lpFuncAddress;

			i++;

		}

		pImportTable++;

	}

	return TRUE;
}

BOOL DoImportTablex32(IN PVOID lpBaseAddress)
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG64)pDosHeader +

		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


	// ѭ������DLL������е�DLL����ȡ������еĺ�����ַ

	PCHAR lpDllName = NULL;

	HMODULE hDll = NULL;

	PIMAGE_THUNK_DATA32 lpImportNameArray = NULL;

	PIMAGE_IMPORT_BY_NAME lpImportByName = NULL;

	PIMAGE_THUNK_DATA32 lpImportFuncAddrArray = NULL;

	ULONG64 lpFuncAddress = NULL;

	ULONG i = 0;

	CHAR lpImportByName_Name[100];



	while (TRUE)
	{

		if (0 == pImportTable->OriginalFirstThunk)

		{

			break;

		}


		// ��ȡ�������DLL�����Ʋ�����DLL

		lpDllName = (PCHAR)((ULONG64)pDosHeader + pImportTable->Name);

		UNICODE_STRING ustr = { 0 };

		STRING strtemp = { 0 };

		RtlInitString(&strtemp, lpDllName);

		RtlAnsiStringToUnicodeString(&ustr, &strtemp, TRUE);

		PEPROCESS pEprocess = NULL;

		KAPC_STATE KPCR = { 0 };

		GetModuleHandlex32(&ustr, &pEprocess, &hDll);

		RtlFreeUnicodeString(&ustr);

		if (NULL == hDll)
		{

			pImportTable++;

			continue;

		}



		i = 0;

		// ��ȡOriginalFirstThunk�Լ���Ӧ�ĵ��뺯�����Ʊ��׵�ַ

		lpImportNameArray = (PIMAGE_THUNK_DATA32)((ULONG64)pDosHeader + pImportTable->OriginalFirstThunk);

		// ��ȡFirstThunk�Լ���Ӧ�ĵ��뺯����ַ���׵�ַ

		lpImportFuncAddrArray = (PIMAGE_THUNK_DATA32)((ULONG64)pDosHeader + pImportTable->FirstThunk);

		while (TRUE)
		{

			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{

				break;

			}


			// ��ȡIMAGE_IMPORT_BY_NAME�ṹ

			lpImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG64)pDosHeader + lpImportNameArray[i].u1.AddressOfData);

			memset(lpImportByName_Name, 0, sizeof(char) * 100);

			memcpy(lpImportByName_Name, lpImportByName->Name, strlen(lpImportByName->Name));


			// �жϵ�����������ŵ������Ǻ������Ƶ���

			if (IMAGE_ORDINAL_FLAG32 & lpImportNameArray[i].u1.Ordinal)
			{

				// ��ŵ���

				// ��IMAGE_THUNK_DATAֵ�����λΪ1ʱ����ʾ��������ŷ�ʽ���룬��ʱ����λ��������һ���������
				KeStackAttachProcess(pEprocess, &KPCR);

				lpFuncAddress = MmGetProcAddressx32(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));

				KeUnstackDetachProcess(&KPCR);
			}
			else
			{

				// ���Ƶ���
				KeStackAttachProcess(pEprocess, &KPCR);

				lpFuncAddress = MmGetProcAddressx32(hDll, (LPCSTR)lpImportByName_Name);

				KeUnstackDetachProcess(&KPCR);
			}

			// ע��˴��ĺ�����ַ��ĸ�ֵ��Ҫ����PE��ʽ����װ�أ���Ҫ�����ˣ�����

			lpImportFuncAddrArray[i].u1.Function = (ULONG)lpFuncAddress;

			i++;

		}

		pImportTable++;

	}

	return TRUE;
}



// �޸�PE�ļ����ػ�ַIMAGE_NT_HEADERS.OptionalHeader.ImageBase

// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ

// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE

BOOL SetImageBasex64(IN PVOID lpBaseAddress)
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	pNtHeaders->OptionalHeader.ImageBase = (ULONG64)lpBaseAddress;



	return TRUE;

}

BOOL SetImageBasex32(IN PVOID lpBaseAddress)
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	pNtHeaders->OptionalHeader.ImageBase = (ULONG)lpBaseAddress;


	return TRUE;

}




// �õ�DLL����ں���DllMain,������ַ��ΪPE�ļ�����ڵ�IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint

// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ

// ����ֵ: �ɹ�������ڵ��ַ��ʧ�ܷ���NULL

PVOID GetDllMainBasex64(IN PVOID lpBaseAddress)
{
	PVOID DllMain = NULL;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	DllMain = ((ULONG64)lpBaseAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

	return DllMain;
}

PVOID GetDllMainBasex32(IN PVOID lpBaseAddress)
{
	PVOID DllMain = NULL;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	DllMain = ((ULONG64)lpBaseAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

	return DllMain;
}

// ģ��MmGetProcAddress��ȡ�ڴ�DLL�ĵ�������

// lpBaseAddress: �ڴ�DLL�ļ����ص������еļ��ػ�ַ

// lpszFuncName: ��������������

// ����ֵ: ���ص��������ĵĵ�ַ

PVOID MmGetProcAddressx64(IN HMODULE lpBaseAddress, IN PCHAR lpszFuncName)
{

	PVOID lpFunc = NULL;

	// ��ȡ������

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	// ��ȡ�����������
	//�����������Ʊ�RVA:�洢�������ַ������ڵĵ�ַ(��Ԫ�ؿ��Ϊ4���ܴ�СΪNumberOfNames * 4)
	PULONG lpAddressOfNamesArray = (PULONG)((ULONG64)pDosHeader + pExportTable->AddressOfNames);

	PCHAR lpFuncName = NULL;


	//����������ű�RVA:�洢�������(��Ԫ�ؿ��Ϊ2���ܴ�СΪNumberOfNames * 2)
	PUSHORT lpAddressOfNameOrdinalsArray = (PUSHORT)((ULONG64)pDosHeader + pExportTable->AddressOfNameOrdinals);

	USHORT wHint = 0;

	//����������ַ��RVA:�洢���е���������ַ(��Ԫ�ؿ��Ϊ4���ܴ�СNumberOfFunctions * 4)
	PULONG lpAddressOfFunctionsArray = (PULONG)((ULONG64)pDosHeader + pExportTable->AddressOfFunctions);


	//�Ժ������ֵ����ĺ�������
	ULONG dwNumberOfNames = pExportTable->NumberOfNames;


	DWORD dwBase = pExportTable->Base;

	DWORD dwExportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	DWORD dwExportSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;


	ULONG i = 0;

	//��һ���ǰ���ʲô��ʽ����������or������ţ����麯����ַ��

	ULONG64 dwName = (ULONG64)lpszFuncName;
	// ����������ĵ�������������, ������ƥ��

	if ((dwName & 0xFFFFFFFFFFFF0000) == 0)
	{
		goto $index;
	}


	// ����������ĵ�������������, ������ƥ��

	for (i = 0; i < dwNumberOfNames; i++)
	{

		lpFuncName = (PCHAR)((ULONG64)pDosHeader + lpAddressOfNamesArray[i]);

		if (0 == strcmp(lpFuncName, lpszFuncName))
		{

			// ��ȡ����������ַ

			wHint = lpAddressOfNameOrdinalsArray[i];

			lpFunc = (PVOID)((ULONG64)pDosHeader + lpAddressOfFunctionsArray[wHint]);

			goto $exit;

			break;

		}

	}

$index:

	//�����ͨ������ŵķ�ʽ���麯����ַ��

	if (dwName < dwBase || dwName >(dwBase + pExportTable->NumberOfFunctions - 1))
	{
		return 0;
	}

	lpFunc = (PCHAR)((ULONG64)pDosHeader + lpAddressOfFunctionsArray[dwName - dwBase]);



$exit:
	//�жϵõ��ĵ�ַ��û��Խ��

	if ((ULONG64)lpFunc < (dwExportRVA + (ULONG64)pDosHeader) || (ULONG64)lpFunc >(dwExportRVA + (ULONG64)pDosHeader + dwExportSize))
	{
		return lpFunc;
	}


	CHAR pTempDll[100] = { 0 };

	CHAR pTempFuction[100] = { 0 };

	strcpy(pTempDll, (LPCSTR)lpFunc);

	PCHAR p = strchr(pTempDll, '.');

	if (!p)
	{
		return lpFunc;
	}

	*p = 0;

	strcpy(pTempFuction, p + 1);

	strcat(pTempDll, ".dll");

	HMODULE h;

	UNICODE_STRING ustr = { 0 };

	STRING strTemp = { 0 };

	RtlInitString(&strTemp, pTempDll);

	RtlAnsiStringToUnicodeString(&ustr, &strTemp, TRUE);

	PEPROCESS pEprocess = NULL;

	GetModuleHandlex64(&ustr, &pEprocess, &h);

	RtlFreeUnicodeString(&ustr);

	if (h == NULL)
	{
		return lpFunc;
	}

	KAPC_STATE KPCR = { 0 };

	KeStackAttachProcess(pEprocess, &KPCR);

	PVOID addr = MmGetProcAddressx64((PVOID)h, pTempFuction);

	KeUnstackDetachProcess(&KPCR);

	return addr;
}


PVOID MmGetProcAddressx32(IN HMODULE lpBaseAddress, IN PCHAR lpszFuncName)
{

	PVOID lpFunc = NULL;

	// ��ȡ������

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	// ��ȡ�����������
	//�����������Ʊ�RVA:�洢�������ַ������ڵĵ�ַ(��Ԫ�ؿ��Ϊ4���ܴ�СΪNumberOfNames * 4)
	PULONG lpAddressOfNamesArray = (PULONG)((ULONG64)pDosHeader + pExportTable->AddressOfNames);

	PCHAR lpFuncName = NULL;


	//����������ű�RVA:�洢�������(��Ԫ�ؿ��Ϊ2���ܴ�СΪNumberOfNames * 2)
	PUSHORT lpAddressOfNameOrdinalsArray = (PUSHORT)((ULONG64)pDosHeader + pExportTable->AddressOfNameOrdinals);

	USHORT wHint = 0;

	//����������ַ��RVA:�洢���е���������ַ(��Ԫ�ؿ��Ϊ4���ܴ�СNumberOfFunctions * 4)
	PULONG lpAddressOfFunctionsArray = (PULONG)((ULONG64)pDosHeader + pExportTable->AddressOfFunctions);


	//�Ժ������ֵ����ĺ�������
	ULONG dwNumberOfNames = pExportTable->NumberOfNames;

	DWORD dwBase = pExportTable->Base;

	DWORD dwExportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	DWORD dwExportSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;


	ULONG i = 0;

	//��һ���ǰ���ʲô��ʽ����������or������ţ����麯����ַ��

	ULONG64 dwName = (ULONG64)lpszFuncName;
	// ����������ĵ�������������, ������ƥ��

	if ((dwName & 0xFFFFFFFFFFFF0000) == 0)
	{
		goto $index;
	}


	// ����������ĵ�������������, ������ƥ��

	for (i = 0; i < dwNumberOfNames; i++)
	{

		lpFuncName = (PCHAR)((ULONG64)pDosHeader + lpAddressOfNamesArray[i]);

		if (0 == strcmp(lpFuncName, lpszFuncName))
		{

			// ��ȡ����������ַ

			wHint = lpAddressOfNameOrdinalsArray[i];

			lpFunc = (PVOID)((ULONG64)pDosHeader + lpAddressOfFunctionsArray[wHint]);

			goto $exit;

			break;

		}

	}

$index:

	//�����ͨ������ŵķ�ʽ���麯����ַ��

	if (dwName < dwBase || dwName >(dwBase + pExportTable->NumberOfFunctions - 1))
	{
		return 0;
	}

	lpFunc = (PCHAR)((ULONG64)pDosHeader + lpAddressOfFunctionsArray[dwName - dwBase]);



$exit:
	//�жϵõ��ĵ�ַ��û��Խ��

	if ((ULONG64)lpFunc < (dwExportRVA + (ULONG64)pDosHeader) || (ULONG64)lpFunc >(dwExportRVA + (ULONG64)pDosHeader + dwExportSize))
	{
		return lpFunc;
	}


	CHAR pTempDll[100] = { 0 };

	CHAR pTempFuction[100] = { 0 };

	strcpy(pTempDll, (LPCSTR)lpFunc);

	PCHAR p = strchr(pTempDll, '.');

	if (!p)
	{
		return lpFunc;
	}

	*p = 0;

	strcpy(pTempFuction, p + 1);

	strcat(pTempDll, ".dll");

	HMODULE h;

	UNICODE_STRING ustr = { 0 };

	STRING strTemp = { 0 };

	RtlInitString(&strTemp, pTempDll);

	RtlAnsiStringToUnicodeString(&ustr, &strTemp, TRUE);

	PEPROCESS pEprocess = NULL;

	GetModuleHandlex32(&ustr, &pEprocess, &h);

	RtlFreeUnicodeString(&ustr);

	if (h == NULL)
	{
		return lpFunc;
	}

	KAPC_STATE KPCR = { 0 };

	KeStackAttachProcess(pEprocess, &KPCR);

	PVOID addr = MmGetProcAddressx32((PVOID)h, pTempFuction);

	KeUnstackDetachProcess(&KPCR);

	return addr;
}


BOOL MmErasePeInfo(IN PVOID lpBaseAddress)
{

	memset(lpBaseAddress, 0, 1024);

	return 0;
}





