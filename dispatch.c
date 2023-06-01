#pragma once

#include"dispatch.h"

NTSTATUS DeviceControlDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{

    UNREFERENCED_PARAMETER(pDevObj);

    UNREFERENCED_PARAMETER(pIrp);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    PIO_STACK_LOCATION pIrqlStack;

    ULONG uIoControlCode;

    PVOID pIoBuffer;

    ULONG uInLength;

    ULONG uOutLength;

    //获取IRP教据

    pIrqlStack = IoGetCurrentIrpStackLocation(pIrp);

    //获取控制码

    uIoControlCode = pIrqlStack->Parameters.DeviceIoControl.IoControlCode;

    //获取缓冲区地址(输入和输出的缓冲区都是一个

    pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;

    //3环发送的数据字节数

    uInLength = pIrqlStack->Parameters.DeviceIoControl.InputBufferLength;

    //0环发送的数据字节数

    uOutLength = pIrqlStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (uIoControlCode)
    {

    case APPCTRL:


        status = STATUS_SUCCESS;
 
        break;

    default:

        break;
    }


    //设置返回状态，否则默认是失败

    pIrp->IoStatus.Status = status;

    pIrp->IoStatus.Information = 0;    //返回给3环多少字节数据，没有填0

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DeviceCreateDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDevObj);

    UNREFERENCED_PARAMETER(pIrp);

    DbgPrint("Create Success!\n");

    //设置返回状态，否则默认是失败

    pIrp->IoStatus.Status = STATUS_SUCCESS;

    pIrp->IoStatus.Information = 0;    //返回给3环多少字节数据，没有填0

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}



NTSTATUS DeviceCloseDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{

    UNREFERENCED_PARAMETER(pDevObj);

    UNREFERENCED_PARAMETER(pIrp);

    DbgPrint("Close Success!\n");

    //设置返回状态，否则默认是失败

    pIrp->IoStatus.Status = STATUS_SUCCESS;

    pIrp->IoStatus.Information = 0;    //返回给3环多少字节数据，没有填0

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}