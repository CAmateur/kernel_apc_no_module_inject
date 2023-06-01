#include"global_vars.h"

VOID GlobalVarsInital()
{
	memset(&globalVars, 0, sizeof(GlobalVars));

	return;
}

VOID GlobalVarsFree()
{
	if (globalVars.peBuffer)
		ExFreePool(globalVars.peBuffer);

	return;
}
