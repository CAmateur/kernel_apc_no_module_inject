#pragma once

#ifndef DISPATCH

#define DISPATCH

#include<ntifs.h>

#include"declare_etc.h"

NTSTATUS DeviceControlDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp);
				
NTSTATUS DeviceCreateDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp);
		 		
NTSTATUS DeviceCloseDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp);

#endif