#ifndef SETUP_MANAGER_H
#define SETUP_MANAGER_H

#include "BootBypass.h"
#include "SystemUtils.h"

// Updates the live (volatile) DeviceGuard registry key Enabled value.
// Cosmetic: makes security tools report correct HVCI state without a reboot.
NTSTATUS SetHVCIRegistryFlag(BOOLEAN enable);

// Locates kvc.sys in DriverStore\FileRepository via "avc.inf_amd64_*" wildcard.
// outPath receives the full NT path on success.
BOOLEAN FindKvcSysInDriverStore(PWSTR outPath, SIZE_T outPathLen);

// Returns the NT path to kvc.sys (DriverStore preferred, System32\drivers fallback).
BOOLEAN FindKvcSysPath(PWSTR outPath, SIZE_T outPathLen);

// Deletes the kvc.sys SCM registry key left by ExecuteAutoPatchLoad.
NTSTATUS CleanupOmniDriver(void);

// Checks if HVCI is active; if so, patches the SYSTEM hive and reboots.
// Returns TRUE if a reboot was initiated (caller must terminate).
BOOLEAN CheckAndDisableHVCI(void);

// Patches SYSTEM hive to re-enable HVCI for the next boot (RestoreHVCI=YES path).
NTSTATUS RestoreHVCI(void);

#endif
