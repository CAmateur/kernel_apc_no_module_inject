#pragma once
#ifndef _MM_LOAD_DLL_H_

#define _MM_LOAD_DLL_H_

#include<ntifs.h>

#include"pe.h"

#include"enum_utils.h"

typedef ULONG64 HMODULE;

// 模拟LoadLibrary加载内存DLL文件到进程中

// lpData: 内存中未拉伸的PE文件数据内存地址

// pBufferMemImagePe: 存放拉伸后的PE文件数据内存地址

// 返回值: 成功返回TRUE，否则返回FALSE

BOOL MmPEtoMemImagePex64(IN PVOID lpData, IN PVOID pBufferMemImagePe);

BOOL MmPEtoMemImagePex32(IN PVOID lpData, IN PVOID pBufferMemImagePe);

// 根据PE结构,获取PE文件加载到内存后的镜像大小

// lpData: 内存中未拉伸的PE文件数据内存地址

// 返回值: 返回PE文件结构中IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage值的大小

ULONG GetSizeOfImagex64(IN PVOID lpData);

ULONG GetSizeOfImagex32(IN PVOID lpData);



// 将未拉伸的PE内存数据按SectionAlignment大小对齐映射到lpBaseAddress指向的内存中

// lpData: 内存DLL文件数据的基址

// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址

// 返回值: 成功返回TRUE，否则返回FALSE

BOOL MmMapFilex64(IN PVOID lpData, IN PVOID lpBaseAddress);

BOOL MmMapFilex32(IN PVOID lpData, IN PVOID lpBaseAddress);



// 修改PE文件重定位表信息

// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址

// 返回值: 成功返回TRUE，否则返回FALSE

BOOL DoRelocationTablex64(IN PVOID lpBaseAddress);

BOOL DoRelocationTablex32(IN PVOID lpBaseAddress);

// 填写PE文件导入表信息

// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址

// 返回值: 成功返回TRUE，否则返回FALSE

BOOL DoImportTablex64(IN PVOID lpBaseAddress);

BOOL DoImportTablex32(IN PVOID lpBaseAddress);

// 修改PE文件加载基址IMAGE_NT_HEADERS.OptionalHeader.ImageBase

// 返回值: 成功返回TRUE，否则返回FALSE

BOOL SetImageBasex64(IN PVOID lpBaseAddress);

BOOL SetImageBasex32(IN PVOID lpBaseAddress);




// 得到DLL的入口函数DllMain,函数地址即为PE文件的入口点IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint

// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址

// 返回值: 成功返回入口点地址，失败返回NULL

PVOID GetDllMainBasex64(IN PVOID lpBaseAddress);

PVOID GetDllMainBasex32(IN PVOID lpBaseAddress);


// 模拟GetProcAddress获取内存DLL的导出函数

// lpBaseAddress: 内存DLL文件加载到进程中的加载基址

// lpszFuncName: 导出函数的名字

// 返回值: 返回导出函数的的地址

PVOID MmGetProcAddressx64(IN HMODULE lpBaseAddress, IN PCHAR lpszFuncName);

PVOID MmGetProcAddressx32(IN HMODULE lpBaseAddress, IN PCHAR lpszFuncName);

BOOL MmErasePeInfo(IN PVOID lpBaseAddress);


#endif
