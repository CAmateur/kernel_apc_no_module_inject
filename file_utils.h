#pragma once

#ifndef FILE_UTILS

#define FILE_UTILS

#include<ntifs.h>

//filePathΪDLL�ļ��ڵ����ϵ�·��

//ppebufferΪδ�����PE��������

NTSTATUS GetPeFileToBuffer(CONST IN  PCHAR filePath, OUT PVOID* pPeBuffer);

#endif