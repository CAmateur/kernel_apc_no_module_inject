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

    //��ȡIRP�̾�

    pIrqlStack = IoGetCurrentIrpStackLocation(pIrp);

    //��ȡ������

    uIoControlCode = pIrqlStack->Parameters.DeviceIoControl.IoControlCode;

    //��ȡ��������ַ(���������Ļ���������һ��

    pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;

    //3�����͵������ֽ���

    uInLength = pIrqlStack->Parameters.DeviceIoControl.InputBufferLength;

    //0�����͵������ֽ���

    uOutLength = pIrqlStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (uIoControlCode)
    {

    case APPCTRL:


        status = STATUS_SUCCESS;
 
        break;

    default:

        break;
    }


    //���÷���״̬������Ĭ����ʧ��

    pIrp->IoStatus.Status = status;

    pIrp->IoStatus.Information = 0;    //���ظ�3�������ֽ����ݣ�û����0

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DeviceCreateDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDevObj);

    UNREFERENCED_PARAMETER(pIrp);

    DbgPrint("Create Success!\n");

    //���÷���״̬������Ĭ����ʧ��

    pIrp->IoStatus.Status = STATUS_SUCCESS;

    pIrp->IoStatus.Information = 0;    //���ظ�3�������ֽ����ݣ�û����0

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}



NTSTATUS DeviceCloseDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{

    UNREFERENCED_PARAMETER(pDevObj);

    UNREFERENCED_PARAMETER(pIrp);

    DbgPrint("Close Success!\n");

    //���÷���״̬������Ĭ����ʧ��

    pIrp->IoStatus.Status = STATUS_SUCCESS;

    pIrp->IoStatus.Information = 0;    //���ظ�3�������ֽ����ݣ�û����0

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}