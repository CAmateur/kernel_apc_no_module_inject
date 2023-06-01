#pragma once

#ifndef FILE_UTILS

#define FILE_UTILS

#include<ntifs.h>

//filePath为DLL文件在电脑上的路径

//ppebuffer为未拉伸的PE缓存数据

NTSTATUS GetPeFileToBuffer(CONST IN  PCHAR filePath, OUT PVOID* pPeBuffer);

#endif