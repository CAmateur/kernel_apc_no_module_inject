#pragma once

#include"kernel_mm_load_dll.h"



// 模拟LoadLibrary加载内存DLL文件到进程中

// lpData: 内存DLL文件数据的基址

// dwSize: 内存DLL文件拉伸展开后的大小

// 返回值: 内存DLL加载到进程的加载基址

BOOL MmPEtoMemImagePex64(IN PVOID lpData, IN PVOID pBufferMemImagePe)
{

	PVOID lpBaseAddress = pBufferMemImagePe;

	// 获取镜像大小

	ULONG dwSizeOfImage = GetSizeOfImagex64(lpData);


	if (NULL == lpBaseAddress)
	{

		DbgPrint("ppBufferMemImagePe is NULL!\n");

		return FALSE;

	}

	// 将内存DLL数据按SectionAlignment大小对齐映射到进程内存中

	if (FALSE == MmMapFilex64(lpData, lpBaseAddress))
	{

		DbgPrint("MmMapFile Failed!\n");

		return FALSE;

	}

	// 修改PE文件重定位表信息

	if (FALSE == DoRelocationTablex64(lpBaseAddress))
	{
		DbgPrint("DoRelocationTable Failed!\n");

		return FALSE;

	}


	// 填写PE文件导入表信息

	if (FALSE == DoImportTablex64(lpBaseAddress))
	{

		DbgPrint("DoImportTable  Failed!\n");

		return FALSE;

	}


	//设置拉伸后PE的ImageBase

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

	// 获取镜像大小

	ULONG dwSizeOfImage = GetSizeOfImagex32(lpData);

	if (NULL == lpBaseAddress)
	{

		DbgPrint("ppBufferMemImagePe is NULL!\n");

		return FALSE;

	}

	// 将内存DLL数据按SectionAlignment大小对齐映射到进程内存中

	if (FALSE == MmMapFilex32(lpData, lpBaseAddress))
	{

		DbgPrint("MmMapFile Failed!\n");

		return FALSE;

	}

	// 修改PE文件重定位表信息

	if (FALSE == DoRelocationTablex32(lpBaseAddress))
	{
		DbgPrint("DoRelocationTable Failed!\n");

		return FALSE;

	}

	// 填写PE文件导入表信息

	if (FALSE == DoImportTablex32(lpBaseAddress))
	{
		DbgPrint("DoImportTable  Failed!\n");

		return FALSE;

	}

	//设置拉伸后PE的ImageBase

	if (FALSE == SetImageBasex32(lpBaseAddress))
	{

		DbgPrint("SetImageBase  Failed!\n");

		return FALSE;
	}

	return TRUE;
}

// 根据PE结构,获取PE文件加载到内存后的镜像大小

// lpData: 内存DLL文件数据的基址

// 返回值: 返回PE文件结构中IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage值的大小

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


// 将内存DLL数据按SectionAlignment大小对齐映射到进程内存中

// lpData: 内存DLL文件数据的基址

// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址

// 返回值: 成功返回TRUE，否则返回FALSE

BOOL MmMapFilex64(IN PVOID lpData, IN PVOID lpBaseAddress)
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpData;

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	// 获取SizeOfHeaders的值: 所有头+节表头的大小

	ULONG dwSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;

	// 获取节表的数量

	USHORT wNumberOfSections = pNtHeaders->FileHeader.NumberOfSections;

	// 获取第一个节表头的地址

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG64)pNtHeaders + sizeof(IMAGE_NT_HEADERS64));

	// 加载 所有头+节表头的大小

	RtlCopyMemory(lpBaseAddress, lpData, dwSizeOfHeaders);

	// 对齐SectionAlignment循环加载节表

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

	// 获取SizeOfHeaders的值: 所有头+节表头的大小

	ULONG dwSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;

	// 获取节表的数量

	USHORT wNumberOfSections = pNtHeaders->FileHeader.NumberOfSections;

	// 获取第一个节表头的地址

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG64)pNtHeaders + sizeof(IMAGE_NT_HEADERS32));

	// 加载 所有头+节表头的大小

	RtlCopyMemory(lpBaseAddress, lpData, dwSizeOfHeaders);

	// 对齐SectionAlignment循环加载节表

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

// 修改PE文件重定位表信息

// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址

// 返回值: 成功返回TRUE，否则返回FALSE

BOOL DoRelocationTablex64(IN PVOID lpBaseAddress)
{

	/* 重定位表的结构：

		//https://blog.csdn.net/m0_67316550/article/details/123472157

	*/


	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((unsigned long long)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);



	// 判断是否有 重定位表

	if ((PVOID)pLoc == (PVOID)pDosHeader && pLoc->SizeOfBlock == NULL)

	{

		// 重定位表 为空

		return TRUE;

	}



	while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表

	{

		USHORT* pLocData = (USHORT*)((PUCHAR)pLoc + sizeof(IMAGE_BASE_RELOCATION));

		//计算本节需要修正的重定位项（地址）的数目

		int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);



		for (int i = 0; i < nNumberOfReloc; i++)

		{

			// 每个WORD由两部分组成。高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值。

			// 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置。


			//在64位系统中，这个值为0x0000A000
			if ((ULONG)(pLocData[i] & 0x0000F000) == 0x0000A000) //这是一个需要修正的地址

			{

				// 32位dll重定位，IMAGE_REL_BASED_HIGHLOW

				// 对于x86的可执行文件，所有的基址重定位都是IMAGE_REL_BASED_HIGHLOW类型的。



				ULONG64* pAddress = (ULONG64*)((PUCHAR)pDosHeader + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));

				ULONG64 dwDelta = (ULONG64)pDosHeader - pNtHeaders->OptionalHeader.ImageBase;

				*pAddress += dwDelta;

			}

		}

		//转移到下一个节进行处理

		pLoc = (PIMAGE_BASE_RELOCATION)((PUCHAR)pLoc + pLoc->SizeOfBlock);

	}



	return TRUE;

}

BOOL DoRelocationTablex32(IN PVOID lpBaseAddress)
{

	/* 重定位表的结构：

		//https://blog.csdn.net/m0_67316550/article/details/123472157

	*/


	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((ULONG64)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);



	// 判断是否有 重定位表

	if ((PVOID)pLoc == (PVOID)pDosHeader && pLoc->SizeOfBlock == NULL)

	{

		// 重定位表 为空

		return TRUE;

	}



	while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表

	{

		USHORT* pLocData = (USHORT*)((PUCHAR)pLoc + sizeof(IMAGE_BASE_RELOCATION));

		//计算本节需要修正的重定位项（地址）的数目

		int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);



		for (int i = 0; i < nNumberOfReloc; i++)

		{

			// 每个WORD由两部分组成。高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值。

			// 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置。


			//在64位系统中，这个值为0x0000A000
			if ((ULONG)(pLocData[i] & 0x0000F000) == 0x00003000) //这是一个需要修正的地址

			{

				// 32位dll重定位，IMAGE_REL_BASED_HIGHLOW

				// 对于x86的可执行文件，所有的基址重定位都是IMAGE_REL_BASED_HIGHLOW类型的。



				ULONG64* pAddress = (ULONG64*)((PUCHAR)pDosHeader + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));

				ULONG64 dwDelta = (ULONG64)pDosHeader - pNtHeaders->OptionalHeader.ImageBase;

				*pAddress += dwDelta;

			}

		}

		//转移到下一个节进行处理

		pLoc = (PIMAGE_BASE_RELOCATION)((PUCHAR)pLoc + pLoc->SizeOfBlock);

	}



	return TRUE;

}



// 填写PE文件导入表信息

// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
// https://blog.csdn.net/xuandao_ahfengren/article/details/112272745
// 返回值: 成功返回TRUE，否则返回FALSE

BOOL DoImportTablex64(IN PVOID lpBaseAddress)
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG64)pDosHeader +

		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


	// 循环遍历DLL导入表中的DLL及获取导入表中的函数地址

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

		// 获取导入表中DLL的名称并加载DLL

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

		// 获取OriginalFirstThunk以及对应的导入函数名称表首地址

		lpImportNameArray = (PIMAGE_THUNK_DATA64)((ULONG64)pDosHeader + pImportTable->OriginalFirstThunk);

		// 获取FirstThunk以及对应的导入函数地址表首地址

		lpImportFuncAddrArray = (PIMAGE_THUNK_DATA64)((ULONG64)pDosHeader + pImportTable->FirstThunk);

		while (TRUE)
		{

			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{

				break;

			}

			// 获取IMAGE_IMPORT_BY_NAME结构

			lpImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG64)pDosHeader + lpImportNameArray[i].u1.AddressOfData);

			memset(lpImportByName_Name, 0, sizeof(char) * 100);

			memcpy(lpImportByName_Name, lpImportByName->Name, strlen(lpImportByName->Name));


			// 判断导出函数是序号导出还是函数名称导出

			if (IMAGE_ORDINAL_FLAG64 & lpImportNameArray[i].u1.Ordinal)
			{

				// 序号导出

				// 当IMAGE_THUNK_DATA值的最高位为1时，表示函数以序号方式输入，这时，低位被看做是一个函数序号
				KeStackAttachProcess(pEprocess, &KPCR);

				lpFuncAddress = MmGetProcAddressx64(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));

				KeUnstackDetachProcess(&KPCR);
			}
			else
			{

				// 名称导出
				KeStackAttachProcess(pEprocess, &KPCR);

				lpFuncAddress = MmGetProcAddressx64(hDll, (LPCSTR)lpImportByName_Name);

				KeUnstackDetachProcess(&KPCR);
			}

			// 注意此处的函数地址表的赋值，要对照PE格式进行装载，不要理解错了！！！

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


	// 循环遍历DLL导入表中的DLL及获取导入表中的函数地址

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


		// 获取导入表中DLL的名称并加载DLL

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

		// 获取OriginalFirstThunk以及对应的导入函数名称表首地址

		lpImportNameArray = (PIMAGE_THUNK_DATA32)((ULONG64)pDosHeader + pImportTable->OriginalFirstThunk);

		// 获取FirstThunk以及对应的导入函数地址表首地址

		lpImportFuncAddrArray = (PIMAGE_THUNK_DATA32)((ULONG64)pDosHeader + pImportTable->FirstThunk);

		while (TRUE)
		{

			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{

				break;

			}


			// 获取IMAGE_IMPORT_BY_NAME结构

			lpImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG64)pDosHeader + lpImportNameArray[i].u1.AddressOfData);

			memset(lpImportByName_Name, 0, sizeof(char) * 100);

			memcpy(lpImportByName_Name, lpImportByName->Name, strlen(lpImportByName->Name));


			// 判断导出函数是序号导出还是函数名称导出

			if (IMAGE_ORDINAL_FLAG32 & lpImportNameArray[i].u1.Ordinal)
			{

				// 序号导出

				// 当IMAGE_THUNK_DATA值的最高位为1时，表示函数以序号方式输入，这时，低位被看做是一个函数序号
				KeStackAttachProcess(pEprocess, &KPCR);

				lpFuncAddress = MmGetProcAddressx32(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));

				KeUnstackDetachProcess(&KPCR);
			}
			else
			{

				// 名称导出
				KeStackAttachProcess(pEprocess, &KPCR);

				lpFuncAddress = MmGetProcAddressx32(hDll, (LPCSTR)lpImportByName_Name);

				KeUnstackDetachProcess(&KPCR);
			}

			// 注意此处的函数地址表的赋值，要对照PE格式进行装载，不要理解错了！！！

			lpImportFuncAddrArray[i].u1.Function = (ULONG)lpFuncAddress;

			i++;

		}

		pImportTable++;

	}

	return TRUE;
}



// 修改PE文件加载基址IMAGE_NT_HEADERS.OptionalHeader.ImageBase

// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址

// 返回值: 成功返回TRUE，否则返回FALSE

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




// 得到DLL的入口函数DllMain,函数地址即为PE文件的入口点IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint

// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址

// 返回值: 成功返回入口点地址，失败返回NULL

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

// 模拟MmGetProcAddress获取内存DLL的导出函数

// lpBaseAddress: 内存DLL文件加载到进程中的加载基址

// lpszFuncName: 导出函数的名字

// 返回值: 返回导出函数的的地址

PVOID MmGetProcAddressx64(IN HMODULE lpBaseAddress, IN PCHAR lpszFuncName)
{

	PVOID lpFunc = NULL;

	// 获取导出表

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	// 获取导出表的数据
	//导出函数名称表RVA:存储函数名字符串所在的地址(表元素宽度为4，总大小为NumberOfNames * 4)
	PULONG lpAddressOfNamesArray = (PULONG)((ULONG64)pDosHeader + pExportTable->AddressOfNames);

	PCHAR lpFuncName = NULL;


	//导出函数序号表RVA:存储函数序号(表元素宽度为2，总大小为NumberOfNames * 2)
	PUSHORT lpAddressOfNameOrdinalsArray = (PUSHORT)((ULONG64)pDosHeader + pExportTable->AddressOfNameOrdinals);

	USHORT wHint = 0;

	//导出函数地址表RVA:存储所有导出函数地址(表元素宽度为4，总大小NumberOfFunctions * 4)
	PULONG lpAddressOfFunctionsArray = (PULONG)((ULONG64)pDosHeader + pExportTable->AddressOfFunctions);


	//以函数名字导出的函数个数
	ULONG dwNumberOfNames = pExportTable->NumberOfNames;


	DWORD dwBase = pExportTable->Base;

	DWORD dwExportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	DWORD dwExportSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;


	ULONG i = 0;

	//查一下是按照什么方式（函数名称or函数序号）来查函数地址的

	ULONG64 dwName = (ULONG64)lpszFuncName;
	// 遍历导出表的导出函数的名称, 并进行匹配

	if ((dwName & 0xFFFFFFFFFFFF0000) == 0)
	{
		goto $index;
	}


	// 遍历导出表的导出函数的名称, 并进行匹配

	for (i = 0; i < dwNumberOfNames; i++)
	{

		lpFuncName = (PCHAR)((ULONG64)pDosHeader + lpAddressOfNamesArray[i]);

		if (0 == strcmp(lpFuncName, lpszFuncName))
		{

			// 获取导出函数地址

			wHint = lpAddressOfNameOrdinalsArray[i];

			lpFunc = (PVOID)((ULONG64)pDosHeader + lpAddressOfFunctionsArray[wHint]);

			goto $exit;

			break;

		}

	}

$index:

	//这个是通过以序号的方式来查函数地址的

	if (dwName < dwBase || dwName >(dwBase + pExportTable->NumberOfFunctions - 1))
	{
		return 0;
	}

	lpFunc = (PCHAR)((ULONG64)pDosHeader + lpAddressOfFunctionsArray[dwName - dwBase]);



$exit:
	//判断得到的地址有没有越界

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

	// 获取导出表

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((ULONG64)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	// 获取导出表的数据
	//导出函数名称表RVA:存储函数名字符串所在的地址(表元素宽度为4，总大小为NumberOfNames * 4)
	PULONG lpAddressOfNamesArray = (PULONG)((ULONG64)pDosHeader + pExportTable->AddressOfNames);

	PCHAR lpFuncName = NULL;


	//导出函数序号表RVA:存储函数序号(表元素宽度为2，总大小为NumberOfNames * 2)
	PUSHORT lpAddressOfNameOrdinalsArray = (PUSHORT)((ULONG64)pDosHeader + pExportTable->AddressOfNameOrdinals);

	USHORT wHint = 0;

	//导出函数地址表RVA:存储所有导出函数地址(表元素宽度为4，总大小NumberOfFunctions * 4)
	PULONG lpAddressOfFunctionsArray = (PULONG)((ULONG64)pDosHeader + pExportTable->AddressOfFunctions);


	//以函数名字导出的函数个数
	ULONG dwNumberOfNames = pExportTable->NumberOfNames;

	DWORD dwBase = pExportTable->Base;

	DWORD dwExportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	DWORD dwExportSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;


	ULONG i = 0;

	//查一下是按照什么方式（函数名称or函数序号）来查函数地址的

	ULONG64 dwName = (ULONG64)lpszFuncName;
	// 遍历导出表的导出函数的名称, 并进行匹配

	if ((dwName & 0xFFFFFFFFFFFF0000) == 0)
	{
		goto $index;
	}


	// 遍历导出表的导出函数的名称, 并进行匹配

	for (i = 0; i < dwNumberOfNames; i++)
	{

		lpFuncName = (PCHAR)((ULONG64)pDosHeader + lpAddressOfNamesArray[i]);

		if (0 == strcmp(lpFuncName, lpszFuncName))
		{

			// 获取导出函数地址

			wHint = lpAddressOfNameOrdinalsArray[i];

			lpFunc = (PVOID)((ULONG64)pDosHeader + lpAddressOfFunctionsArray[wHint]);

			goto $exit;

			break;

		}

	}

$index:

	//这个是通过以序号的方式来查函数地址的

	if (dwName < dwBase || dwName >(dwBase + pExportTable->NumberOfFunctions - 1))
	{
		return 0;
	}

	lpFunc = (PCHAR)((ULONG64)pDosHeader + lpAddressOfFunctionsArray[dwName - dwBase]);



$exit:
	//判断得到的地址有没有越界

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





