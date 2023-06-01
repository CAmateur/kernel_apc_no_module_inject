#pragma once

#include"declare_etc.h"

#include"dispatch.h"

#include"global_vars.h"

#include"kernel_mm_load_dll.h"

#include"enum_utils.h"

#include"apc.h"






NTSTATUS UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT  pNextObj;

	KdPrint(("Enter DriverUnload\n"));

	pNextObj = DriverObject->DeviceObject;// ��һ���豸����ĵ�ַ���������������DeviceObject��

	while (pNextObj != NULL)
	{
		PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pNextObj->DeviceExtension; // �õ��豸��չ  �豸����չ�ṹ��

		//ɾ����������
		UNICODE_STRING pLinkName = pDevExt->ustrSymLinkName;

		IoDeleteSymbolicLink(&pLinkName);

		pNextObj = pNextObj->NextDevice;  // ÿ���豸�����NextDevice���¼����һ���豸����ĵ�ַ

		// ɾ���豸
		IoDeleteDevice(pDevExt->pDevice);// ��������Ҫ��ɾ�����豸����ָ��
	}

	DbgPrint("ж�سɹ�������\n");

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;

	PDEVICE_OBJECT pDevObj;

	PDEVICE_EXTENSION pDevExt;

	UNICODE_STRING devName;

	RtlInitUnicodeString(&devName, DEVICE_NAME);

	DriverObject->DriverUnload = UnloadDriver;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateDispatch;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlDispatch;

	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCloseDispatch;

	status = IoCreateDevice(DriverObject,

		sizeof(DEVICE_EXTENSION),

		&devName,

		FILE_DEVICE_UNKNOWN,

		0, TRUE,

		&pDevObj);

	if (!NT_SUCCESS(status))
		return status;

	pDevObj->Flags |= DO_BUFFERED_IO;

	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;

	pDevExt->pDevice = pDevObj;

	pDevExt->ustrDeviceName = devName;

	UNICODE_STRING symLinkName;

	RtlInitUnicodeString(&symLinkName, SYMBOL_LINK);

	pDevExt->ustrSymLinkName = symLinkName;

	status = IoCreateSymbolicLink(&symLinkName, &devName);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);

		return status;
	}


	GlobalVarsInital();

	//KernelApcMapInjectx64("x64test.exe", "\\??\\C:\\x64dll.dll");

	KernelApcMapInjectx32("x32dbg.exe", "\\??\\C:\\x32dll.dll");

	GlobalVarsFree();
	

	return STATUS_SUCCESS;
}


