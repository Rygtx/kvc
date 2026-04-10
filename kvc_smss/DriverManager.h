#ifndef DRIVER_MANAGER_H
#define DRIVER_MANAGER_H

#include "BootBypass.h"
#include "SystemUtils.h"

// Returns obfuscated driver/device name string from the assembly stealth stub.
// Decoded at runtime from a built-in XOR-encoded literal to avoid plaintext
// service name appearing in the binary image.
extern PWSTR MmGetPoolDiagnosticString(void);

// Returns TRUE if the driver for serviceName is present in the running module list.
BOOLEAN IsDriverLoaded(PCWSTR serviceName);

// Creates the SCM registry key with Type, Start, ErrorControl, ImagePath, DisplayName.
// STATUS_OBJECT_NAME_COLLISION is non-fatal (key already exists from a prior run).
NTSTATUS CreateDriverRegistryEntry(PCWSTR serviceName, PCWSTR imagePath, PCWSTR driverType, PCWSTR startType);

// Creates the registry key then calls NtLoadDriver.
NTSTATUS LoadDriver(PCWSTR serviceName, PCWSTR imagePath, PCWSTR driverType, PCWSTR startType);

// Calls NtUnloadDriver.  Registry key is NOT deleted here; use CleanupOmniDriver.
NTSTATUS UnloadDriver(PCWSTR serviceName);

#endif