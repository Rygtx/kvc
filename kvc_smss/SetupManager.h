#ifndef SETUP_MANAGER_H
#define SETUP_MANAGER_H

#include "BootBypass.h"
#include "SystemUtils.h"

NTSTATUS SetHVCIRegistryFlag(BOOLEAN enable);
BOOLEAN FindKvcSysInDriverStore(PWSTR outPath, SIZE_T outPathLen);
NTSTATUS CleanupOmniDriver(void);
BOOLEAN CheckAndDisableHVCI(void);
NTSTATUS RestoreHVCI(void);

#endif