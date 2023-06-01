#pragma once

#ifndef GLOBAL_VARS

#define GLOBAL_VARS

#include<ntifs.h>


typedef struct _GlobalVars
{

	PVOID peBuffer;

	KEVENT apcEnvent;

	BOOLEAN acpInsert;


}GlobalVars, * PGlobalVars;

GlobalVars globalVars;



VOID GlobalVarsInital();

VOID GlobalVarsFree();

#endif // !GLOBAL_VARS


