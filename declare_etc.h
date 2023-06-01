#pragma once

#ifndef DECLARE_ETC

#define DECLARE_ETC

#include<ntifs.h>


//驱动相关


UNICODE_STRING Devicename;

UNICODE_STRING SymbolLink;

typedef struct _DEVICE_EXTENSION {

	PDEVICE_OBJECT pDevice;

	UNICODE_STRING ustrDeviceName;  //设备名称

	UNICODE_STRING ustrSymLinkName; //符号链接名

} DEVICE_EXTENSION, * PDEVICE_EXTENSION;



#define DEVICE_NAME L"\\Device\\APPKiller"

#define SYMBOL_LINK L"\\??\\APPKiller"

//操作码：0x0-0x7FF 被保留，0x800-0xFFF 可用

#define APPCTRL CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)





#endif