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

	pNextObj = DriverObject->DeviceObject;// 第一个设备对象的地址存在于驱动对象的DeviceObject域

	while (pNextObj != NULL)
	{
		PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pNextObj->DeviceExtension; // 得到设备扩展  设备的扩展结构体

		//删除符号链接
		UNICODE_STRING pLinkName = pDevExt->ustrSymLinkName;

		IoDeleteSymbolicLink(&pLinkName);

		pNextObj = pNextObj->NextDevice;  // 每个设备对象的NextDevice域记录着下一个设备对象的地址

		// 删除设备
		IoDeleteDevice(pDevExt->pDevice);// 参数就是要被删除的设备对象指针
	}

	DbgPrint("卸载成功！！！\n");

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


