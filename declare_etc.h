#pragma once

#ifndef DECLARE_ETC

#define DECLARE_ETC

#include<ntifs.h>


//�������


UNICODE_STRING Devicename;

UNICODE_STRING SymbolLink;

typedef struct _DEVICE_EXTENSION {

	PDEVICE_OBJECT pDevice;

	UNICODE_STRING ustrDeviceName;  //�豸����

	UNICODE_STRING ustrSymLinkName; //����������

} DEVICE_EXTENSION, * PDEVICE_EXTENSION;



#define DEVICE_NAME L"\\Device\\APPKiller"

#define SYMBOL_LINK L"\\??\\APPKiller"

//�����룺0x0-0x7FF ��������0x800-0xFFF ����

#define APPCTRL CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)





#endif