// ============================================================================
// OffsetFinder — offline heuristic scanner for SeCiCallbacks offsets
//
// Reads ntoskrnl.exe from disk (\SystemRoot\System32\ntoskrnl.exe) and
// locates two offsets needed for the DSE bypass:
//
//   Offset_SeCiCallbacks  — RVA of the SeCiCallbacks pointer table in the
//                           kernel's .data section.
//   Offset_SafeFunction   — RVA of a small no-op stub (usually a one-line
//                           return-success helper) used to replace the DSE
//                           callback slot temporarily.
//
// ALGORITHM OVERVIEW:
//   1. ParsePe: validate DOS/NT headers, enumerate sections into PE_CONTEXT.
//   2. FindExportRva: locate KeServiceDescriptorTable or another anchor export
//      to constrain the search region.
//   3. IsRipRelativeLea: scan executable sections for LEA r64,[RIP+disp32]
//      instructions (7-byte form: REX 8D /5 disp32) targeting writable data.
//   4. ScoreZeroingWindow: examine the 96 bytes following each LEA for the
//      pattern: XOR edx,edx / XOR rdx,rdx (zero second arg) + MOV r10d,imm
//      (size arg in range 0x40-0x400) + CALL rel32 — characteristic of a
//      RtlZeroMemory call used to initialize the SeCiCallbacks array.
//   5. FindRuntimeFunctionBounds: use the PE exception directory (.pdata) to
//      find the function that contains the winning LEA; this gives us exact
//      function start/end for the SafeFunction scan.
//   6. FindNearbyQwordStore: within FAST_QWORD_WINDOW bytes after the LEA,
//      look for MOV [RIP+disp32], r/imm64 — the initial store that fills the
//      first callback slot (gap between LEA and store constrains SafeFunction).
//   7. CountSeCiMovs: count distinct MOV targets within the SeCiCallbacks
//      range; a score >= FAST_MIN_SCORE confirms the candidate.
//   8. FindExportRva("RtlpExecuteUmsThread") or similar small stubs: pick the
//      SafeFunction as the nearest export below SeCiCallbacks in the .text
//      section that fits the size / alignment criteria.
//
// FALLBACK: if no candidate scores above FAST_MIN_SCORE, the function returns
// FALSE and the caller falls back to the PDB path or aborts.
//
// This scanner is used at boot when no PDB is cached (OffsetSource=SCAN or
// OffsetSource=AUTO with missing INI offsets).  The scan completes in ~50 ms
// on a cold SSD and in under 5 ms when ntoskrnl.exe is already in the file
// cache from a warm boot.
// ============================================================================

#include "OffsetFinder.h"
#include "SystemUtils.h"

#define SCN_MEM_WRITE   0x80000000    // IMAGE_SCN_MEM_WRITE
#define SCN_MEM_EXECUTE 0x20000000    // IMAGE_SCN_MEM_EXECUTE
#define LEA_LEN         7             // REX 8D /5 disp32 — always 7 bytes
#define STRUCT_OFFSET   4             // SeCiCallbacks[0] is at offset +4 in the table
#define SECI_FLAGS_EXPECTED 0x108     // expected flags DWORD in the callbacks struct
#define FAST_BACK_WINDOW    0x600     // bytes to scan before the LEA for MOV stores
#define FAST_FORWARD_WINDOW 0x40     // bytes to scan after the LEA for initial stores
#define FAST_QWORD_WINDOW   0x20     // window for FindNearbyQwordStore
#define FAST_MIN_SCORE      110      // minimum CountSeCiMovs score to accept a candidate

typedef struct _SECTION_INFO {
    ULONG VirtualAddress;
    ULONG VirtualSize;
    ULONG RawPointer;
    ULONG RawSize;
    ULONG Characteristics;
} SECTION_INFO;

typedef struct _PE_CONTEXT {
    PUCHAR Base;
    SIZE_T Size;
    PIMAGE_NT_HEADERS64 NtHeaders;
    SECTION_INFO Sections[32];
    ULONG SectionCount;
} PE_CONTEXT;

typedef struct _RUNTIME_FUNCTION_INFO {
    ULONG BeginRva;
    ULONG EndRva;
    ULONG BeginOffset;
    ULONG EndOffsetExclusive;
} RUNTIME_FUNCTION_INFO;

typedef struct _RIP_RELATIVE_STORE {
    ULONG FileOffset;
    ULONG Rva;
    ULONG Length;
    ULONG Imm32;
    ULONG TargetRva;
    LONG TargetSectionIndex;
    BOOLEAN IsQword;
} RIP_RELATIVE_STORE;

static BOOLEAN IsWritableData(PE_CONTEXT* ctx, ULONG rva);
static LONG FindSectionIndexForRva(PE_CONTEXT* ctx, ULONG rva);
static BOOLEAN FileOffsetToRva(PE_CONTEXT* ctx, ULONG fileOffset, PULONG rva, PLONG sectionIndex);
static BOOLEAN ReadRipRelativeStore(PE_CONTEXT* ctx, ULONG fileOffset, RIP_RELATIVE_STORE* store);
static BOOLEAN FindNearbyQwordStore(
    PE_CONTEXT* ctx,
    ULONG startOffset,
    ULONG endOffsetExclusive,
    PULONG qwordGap,
    RIP_RELATIVE_STORE* qwordStore);
static BOOLEAN FindRuntimeFunctionBounds(PE_CONTEXT* ctx, ULONG rva, RUNTIME_FUNCTION_INFO* runtimeInfo);
static SIZE_T MinSize(SIZE_T lhs, SIZE_T rhs);
static ULONG MinUlong(ULONG lhs, ULONG rhs);
static BOOLEAN IsWritableSectionIndex(PE_CONTEXT* ctx, LONG sectionIndex);

// Computes the target RVA of a RIP-relative instruction.
// target = instrRva + instrLen + rel32  (standard x64 RIP-relative formula).
static ULONG ComputeRelTargetRva(ULONG instrRva, ULONG instrLen, LONG rel32) {
    return (ULONG)((__int64)instrRva + (__int64)instrLen + (__int64)rel32);
}

static SIZE_T MinSize(SIZE_T lhs, SIZE_T rhs) {
    return lhs < rhs ? lhs : rhs;
}

static ULONG MinUlong(ULONG lhs, ULONG rhs) {
    return lhs < rhs ? lhs : rhs;
}

// Returns TRUE if the bytes at fileOffset form a RIP-relative LEA:
//   REX.W (0x48-0x4F) 8D /5 disp32  (7 bytes, ModRM = 0bXX000101).
// Only the 7-byte form is matched; shorter LEA encodings cannot target .data.
static BOOLEAN IsRipRelativeLea(PE_CONTEXT* ctx, ULONG fileOffset) {
    PUCHAR p;

    if (fileOffset + LEA_LEN > ctx->Size) {
        return FALSE;
    }

    p = ctx->Base + fileOffset;
    return ((p[0] & 0xF8) == 0x48) &&
           p[1] == 0x8D &&
           ((p[2] & 0xC7) == 0x05);
}

// Scores the 96-byte window following a LEA candidate for RtlZeroMemory call
// characteristics.  Returns 0-3:
//   +1 if XOR edx/rdx (zero arg) is present before the call.
//   +1 if MOV r10d/r9d, imm (size in 0x40-0x400 range) is found.
//   +1 if CALL rel32 appears after both of the above.
// zeroSize receives the size immediate when hasZeroSize is set.
// A score of 3 strongly indicates the LEA feeds a RtlZeroMemory(SeCiCallbacks,N).
static int ScoreZeroingWindow(
    PUCHAR imageBase,
    SIZE_T imageSize,
    ULONG leaFileOffset,
    PULONG zeroSize,
    PBOOLEAN hasZeroSize) {
    int score = 0;
    SIZE_T windowEndOffset = MinSize(imageSize, (SIZE_T)leaFileOffset + 96);
    PUCHAR start = imageBase + leaFileOffset;
    PUCHAR end = imageBase + windowEndOffset;
    PUCHAR zeroPos = end;
    PUCHAR sizePos = end;
    PUCHAR callPos = end;
    PUCHAR p;

    if (zeroSize != NULL) {
        *zeroSize = 0;
    }
    if (hasZeroSize != NULL) {
        *hasZeroSize = FALSE;
    }

    for (p = start; p + 2 <= end; ++p) {
        if ((p[0] == 0x33 && p[1] == 0xD2) ||
            (p[0] == 0x31 && p[1] == 0xD2)) {
            if (p < zeroPos) {
                zeroPos = p;
            }
        }
        if (p + 3 <= end &&
            p[0] == 0x48 &&
            p[1] == 0x33 &&
            p[2] == 0xD2) {
            if (p < zeroPos) {
                zeroPos = p;
            }
        }
    }

    for (p = start; p + 6 <= end; ++p) {
        if (p[0] == 0x41 && p[1] == 0xB8) {
            ULONG imm = *(PULONG)(p + 2);
            if (imm >= 0x40 && imm <= 0x400) {
                sizePos = p;
                if (zeroSize != NULL) {
                    *zeroSize = imm;
                }
                if (hasZeroSize != NULL) {
                    *hasZeroSize = TRUE;
                }
                break;
            }
        }
        if (p + 7 <= end &&
            p[0] == 0x49 &&
            p[1] == 0xC7 &&
            p[2] == 0xC0) {
            ULONG imm = *(PULONG)(p + 3);
            if (imm >= 0x40 && imm <= 0x400) {
                sizePos = p;
                if (zeroSize != NULL) {
                    *zeroSize = imm;
                }
                if (hasZeroSize != NULL) {
                    *hasZeroSize = TRUE;
                }
                break;
            }
        }
    }

    for (p = start; p + 5 <= end; ++p) {
        if (p[0] == 0xE8) {
            callPos = p;
            break;
        }
    }

    if (zeroPos != end) {
        score++;
    }
    if (hasZeroSize != NULL && *hasZeroSize) {
        score++;
    }
    if (callPos != end) {
        PUCHAR earliest = zeroPos < sizePos ? zeroPos : sizePos;
        if (callPos > earliest) {
            score++;
        }
    }

    return score;
}

static LONG FindSectionIndexForRva(PE_CONTEXT* ctx, ULONG rva) {
    ULONG i;

    for (i = 0; i < ctx->SectionCount; i++) {
        ULONG virtualSize = ctx->Sections[i].VirtualSize != 0 ? ctx->Sections[i].VirtualSize : ctx->Sections[i].RawSize;
        if (rva >= ctx->Sections[i].VirtualAddress &&
            rva < ctx->Sections[i].VirtualAddress + virtualSize) {
            return (LONG)i;
        }
    }

    return -1;
}

static BOOLEAN FileOffsetToRva(PE_CONTEXT* ctx, ULONG fileOffset, PULONG rva, PLONG sectionIndex) {
    ULONG i;

    for (i = 0; i < ctx->SectionCount; i++) {
        ULONG start = ctx->Sections[i].RawPointer;
        ULONG end = start + ctx->Sections[i].RawSize;
        if (fileOffset >= start && fileOffset < end) {
            if (rva != NULL) {
                *rva = ctx->Sections[i].VirtualAddress + (fileOffset - start);
            }
            if (sectionIndex != NULL) {
                *sectionIndex = (LONG)i;
            }
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN IsWritableSectionIndex(PE_CONTEXT* ctx, LONG sectionIndex) {
    if (sectionIndex < 0 || (ULONG)sectionIndex >= ctx->SectionCount) {
        return FALSE;
    }

    return (ctx->Sections[sectionIndex].Characteristics & SCN_MEM_WRITE) &&
          !(ctx->Sections[sectionIndex].Characteristics & SCN_MEM_EXECUTE);
}

// Decodes a RIP-relative MOV store at fileOffset.  Two forms are recognised:
//   C7 05 disp32 imm32          — DWORD store (10 bytes)
//   48 C7 05 disp32 imm32       — QWORD store with sign-extended imm32 (11 bytes)
// Fills *store on success; returns FALSE if the bytes don't match either form
// or the file/section bounds are exceeded.
static BOOLEAN ReadRipRelativeStore(PE_CONTEXT* ctx, ULONG fileOffset, RIP_RELATIVE_STORE* store) {
    PUCHAR p;
    ULONG rva;
    LONG sectionIndex;
    ULONG displacementOffset;
    ULONG instructionLength;
    BOOLEAN isQword;
    LONG rel32;

    if (fileOffset + 10 > ctx->Size || store == NULL) {
        return FALSE;
    }

    p = ctx->Base + fileOffset;
    displacementOffset = 0;
    instructionLength = 0;
    isQword = FALSE;

    if (fileOffset + 11 <= ctx->Size &&
        p[0] == 0x48 &&
        p[1] == 0xC7 &&
        p[2] == 0x05) {
        displacementOffset = 3;
        instructionLength = 11;
        isQword = TRUE;
    } else if (p[0] == 0xC7 && p[1] == 0x05) {
        displacementOffset = 2;
        instructionLength = 10;
        isQword = FALSE;
    } else {
        return FALSE;
    }

    if (!FileOffsetToRva(ctx, fileOffset, &rva, &sectionIndex)) {
        return FALSE;
    }

    rel32 = *(PLONG)(p + displacementOffset);

    store->FileOffset = fileOffset;
    store->Rva = rva;
    store->Length = instructionLength;
    store->Imm32 = *(PULONG)(p + displacementOffset + 4);
    store->TargetRva = ComputeRelTargetRva(rva, instructionLength, rel32);
    store->TargetSectionIndex = FindSectionIndexForRva(ctx, store->TargetRva);
    store->IsQword = isQword;
    return TRUE;
}

static ULONG RvaToOffset(PE_CONTEXT* ctx, ULONG rva) {
    ULONG i;

    if (rva == 0) return 0;
    for (i = 0; i < ctx->SectionCount; i++) {
        if (rva >= ctx->Sections[i].VirtualAddress && 
            rva < ctx->Sections[i].VirtualAddress + ctx->Sections[i].RawSize) {
            return ctx->Sections[i].RawPointer + (rva - ctx->Sections[i].VirtualAddress);
        }
    }
    return 0;
}

static BOOLEAN IsWritableData(PE_CONTEXT* ctx, ULONG rva) {
    return IsWritableSectionIndex(ctx, FindSectionIndexForRva(ctx, rva));
}

// Scans up to FAST_QWORD_WINDOW bytes starting from startOffset+1 for a
// QWORD MOV store targeting a writable data section.
// Returns TRUE and fills *qwordStore/*qwordGap on the first match found.
// Used to identify the first callback slot initialisation after a LEA candidate.
static BOOLEAN FindNearbyQwordStore(
    PE_CONTEXT* ctx,
    ULONG startOffset,
    ULONG endOffsetExclusive,
    PULONG qwordGap,
    RIP_RELATIVE_STORE* qwordStore) {
    ULONG maxEnd;
    ULONG fileOffset;

    maxEnd = MinUlong(endOffsetExclusive, startOffset + FAST_QWORD_WINDOW);
    for (fileOffset = startOffset + 1; fileOffset < maxEnd; ++fileOffset) {
        RIP_RELATIVE_STORE store;
        if (!ReadRipRelativeStore(ctx, fileOffset, &store)) {
            continue;
        }
        if (!store.IsQword || !IsWritableSectionIndex(ctx, store.TargetSectionIndex)) {
            continue;
        }

        if (qwordGap != NULL) {
            *qwordGap = fileOffset - startOffset;
        }
        if (qwordStore != NULL) {
            *qwordStore = store;
        }
        return TRUE;
    }

    return FALSE;
}

// Searches the PE exception directory (.pdata) for the RUNTIME_FUNCTION entry
// that contains rva.  Returns the function's begin/end RVAs and corresponding
// file offsets in *runtimeInfo.
// Required because the SafeFunction scan must be limited to a single function
// body — scanning across function boundaries produces false positives.
static BOOLEAN FindRuntimeFunctionBounds(PE_CONTEXT* ctx, ULONG rva, RUNTIME_FUNCTION_INFO* runtimeInfo) {
    IMAGE_DATA_DIRECTORY* exceptionDir;
    ULONG dirOffset;
    ULONG availableEntries;
    ULONG maxEntries;
    ULONG i;

    if (runtimeInfo == NULL) {
        return FALSE;
    }

    exceptionDir = &ctx->NtHeaders->OptionalHeader.DataDirectory[3];
    if (exceptionDir->VirtualAddress == 0 || exceptionDir->Size < 12) {
        return FALSE;
    }

    dirOffset = RvaToOffset(ctx, exceptionDir->VirtualAddress);
    if (dirOffset == 0 || dirOffset >= ctx->Size) {
        return FALSE;
    }

    availableEntries = (ULONG)((ctx->Size - dirOffset) / 12);
    maxEntries = exceptionDir->Size / 12;
    if (availableEntries < maxEntries) {
        maxEntries = availableEntries;
    }

    for (i = 0; i < maxEntries; ++i) {
        PUCHAR entry = ctx->Base + dirOffset + (i * 12);
        ULONG beginRva = *(PULONG)(entry + 0);
        ULONG endRva = *(PULONG)(entry + 4);
        ULONG beginOffset;
        ULONG endOffset;
        LONG beginSection;
        LONG endSection;

        if (beginRva == 0 || endRva <= beginRva) {
            continue;
        }
        if (!(beginRva <= rva && rva < endRva)) {
            continue;
        }

        beginOffset = RvaToOffset(ctx, beginRva);
        endOffset = RvaToOffset(ctx, endRva - 1);
        beginSection = FindSectionIndexForRva(ctx, beginRva);
        endSection = FindSectionIndexForRva(ctx, endRva - 1);
        if (beginOffset == 0 || endOffset == 0) {
            continue;
        }
        if (beginSection < 0 || beginSection != endSection) {
            continue;
        }

        runtimeInfo->BeginRva = beginRva;
        runtimeInfo->EndRva = endRva;
        runtimeInfo->BeginOffset = beginOffset;
        runtimeInfo->EndOffsetExclusive = endOffset + 1;
        return TRUE;
    }

    return FALSE;
}

static ULONG FindExportRva(PE_CONTEXT* ctx, const char* name) {
    IMAGE_DATA_DIRECTORY* exportDir = &ctx->NtHeaders->OptionalHeader.DataDirectory[0];
    if (exportDir->VirtualAddress == 0) return 0;

    ULONG dirOffset = RvaToOffset(ctx, exportDir->VirtualAddress);
    if (dirOffset == 0) return 0;

    PUCHAR exportBase = ctx->Base + dirOffset;
    ULONG count = *(PULONG)(exportBase + 24);
    ULONG funcTableRva = *(PULONG)(exportBase + 28);
    ULONG nameTableRva = *(PULONG)(exportBase + 32);
    ULONG ordTableRva = *(PULONG)(exportBase + 36);

    PULONG functions = (PULONG)(ctx->Base + RvaToOffset(ctx, funcTableRva));
    PULONG names = (PULONG)(ctx->Base + RvaToOffset(ctx, nameTableRva));
    PUSHORT ordinals = (PUSHORT)(ctx->Base + RvaToOffset(ctx, ordTableRva));

    if (!functions || !names || !ordinals) return 0;

    for (ULONG i = 0; i < count; i++) {
        ULONG nameOff = RvaToOffset(ctx, names[i]);
        if (nameOff == 0) continue;

        const char* funcName = (const char*)(ctx->Base + nameOff);
        BOOLEAN match = TRUE;
        ULONG j = 0;
        while (name[j] != 0) {
            if (name[j] != funcName[j]) { match = FALSE; break; }
            j++;
        }
        if (match && funcName[j] == 0) {
             return functions[ordinals[i]];
        }
    }
    return 0;
}

// Validates PE headers and populates ctx->Sections[] from the section table.
// Returns FALSE if the DOS or NT signature is wrong, or if the section table
// would overflow the fixed Sections[32] array (capped silently).
static BOOLEAN ParsePe(PE_CONTEXT* ctx) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ctx->Base;
    if (dos->e_magic != 0x5A4D) return FALSE;

    ctx->NtHeaders = (PIMAGE_NT_HEADERS64)(ctx->Base + dos->e_lfanew);
    if (ctx->NtHeaders->Signature != 0x00004550) return FALSE;

    ctx->SectionCount = ctx->NtHeaders->FileHeader.NumberOfSections;
    if (ctx->SectionCount > 32) ctx->SectionCount = 32;

    PUCHAR sectionTable = (PUCHAR)ctx->NtHeaders + 4 + sizeof(IMAGE_FILE_HEADER) + ctx->NtHeaders->FileHeader.SizeOfOptionalHeader;

    for (ULONG i = 0; i < ctx->SectionCount; i++) {
        PUCHAR entry = sectionTable + (i * 40);
        ctx->Sections[i].VirtualSize = *(PULONG)(entry + 8);
        ctx->Sections[i].VirtualAddress = *(PULONG)(entry + 12);
        ctx->Sections[i].RawSize = *(PULONG)(entry + 16);
        ctx->Sections[i].RawPointer = *(PULONG)(entry + 20);
        ctx->Sections[i].Characteristics = *(PULONG)(entry + 36);
    }
    return TRUE;
}

// Count unique QWORD/DWORD RIP-relative MOV instructions that target
// [seci_rva, seci_rva+0x28) within scan_radius bytes of match_file.
// Returns number of distinct target addresses hit (like CountSeCiMovs in SeCiFinder).
static int CountSeCiMovs(PE_CONTEXT* ctx, ULONG match_file, ULONG seci_rva, ULONG scan_radius) {
    ULONG seci_end = seci_rva + 0x28U;
    ULONG start = match_file > scan_radius ? match_file - scan_radius : 0;
    ULONG end = match_file + scan_radius;
    if (end > (ULONG)ctx->Size) end = (ULONG)ctx->Size;

    // Simple hit set: track up to 64 unique targets (more than enough for SeCi range)
    ULONG targets[64];
    int target_count = 0;
    ULONG index = start;

    while (index + 6 < end) {
        if (index + 11 <= end &&
            ctx->Base[index] == 0x48U &&
            ctx->Base[index + 1] == 0xC7U &&
            ctx->Base[index + 2] == 0x05U) {
            RIP_RELATIVE_STORE store;
            if (ReadRipRelativeStore(ctx, index, &store)) {
                if (seci_rva <= store.TargetRva && store.TargetRva < seci_end) {
                    // Insert unique
                    int found = 0, k;
                    for (k = 0; k < target_count; k++) {
                        if (targets[k] == store.TargetRva) { found = 1; break; }
                    }
                    if (!found && target_count < 64) targets[target_count++] = store.TargetRva;
                }
            }
            index += 11;
            continue;
        }
        if (ctx->Base[index] == 0xC7U && ctx->Base[index + 1] == 0x05U) {
            RIP_RELATIVE_STORE store;
            if (ReadRipRelativeStore(ctx, index, &store)) {
                if (seci_rva <= store.TargetRva && store.TargetRva < seci_end) {
                    int found = 0, k;
                    for (k = 0; k < target_count; k++) {
                        if (targets[k] == store.TargetRva) { found = 1; break; }
                    }
                    if (!found && target_count < 64) targets[target_count++] = store.TargetRva;
                }
            }
            index += 10;
            continue;
        }
        index++;
    }

    return target_count;
}

// Structural scan: exhaustive LEA search across all executable sections.
// For each valid LEA targeting a writable section, ScoreZeroingWindow must
// return 3 (XOR zero + size imm + CALL) to proceed.  The candidate SeCiCallbacks
// RVA is derived as target_rva - STRUCT_OFFSET.  MOV evidence and a nearby
// QWORD store are scored; the highest-scoring candidate wins.
// Returns best seci_rva or 0 if no candidate scores above threshold.
static ULONG FindSeCiStructural(PE_CONTEXT* ctx) {
    #define STRUCTURAL_FORWARD_WINDOW 0x240U
    ULONG best_rva = 0;
    LONG best_score = -1;

    ULONG i;
    for (i = 0; i < ctx->SectionCount; i++) {
        ULONG sectionStart, sectionEnd, lea_file;

        if (!(ctx->Sections[i].Characteristics & SCN_MEM_EXECUTE)) continue;
        sectionStart = ctx->Sections[i].RawPointer;
        sectionEnd = sectionStart + ctx->Sections[i].RawSize;
        if (sectionEnd > (ULONG)ctx->Size) sectionEnd = (ULONG)ctx->Size;

        for (lea_file = sectionStart; lea_file + LEA_LEN <= sectionEnd; ++lea_file) {
            ULONG lea_rva, target_rva, seci_rva, search_end;
            LONG lea_section_idx;
            LONG rel32;
            ULONG zero_size;
            BOOLEAN has_zero_size;
            int zero_score;
            RUNTIME_FUNCTION_INFO runtimeInfo;
            ULONG pos;

            if (!IsRipRelativeLea(ctx, lea_file)) continue;
            if (!FileOffsetToRva(ctx, lea_file, &lea_rva, &lea_section_idx)) continue;

            rel32 = *(PLONG)(ctx->Base + lea_file + 3);
            target_rva = ComputeRelTargetRva(lea_rva, LEA_LEN, rel32);
            if (!IsWritableData(ctx, target_rva)) continue;

            zero_score = ScoreZeroingWindow(ctx->Base, ctx->Size, lea_file, &zero_size, &has_zero_size);
            if (zero_score < 3) continue;

            seci_rva = target_rva - STRUCT_OFFSET;

            if (FindRuntimeFunctionBounds(ctx, lea_rva, &runtimeInfo)) {
                search_end = runtimeInfo.EndOffsetExclusive;
            } else {
                search_end = lea_file + STRUCTURAL_FORWARD_WINDOW;
                if (search_end > (ULONG)ctx->Size) search_end = (ULONG)ctx->Size;
            }

            // Look for a DWORD store at seci_rva within the function
            for (pos = lea_file; pos + 10 <= search_end; ++pos) {
                RIP_RELATIVE_STORE store;
                ULONG qword_gap;
                RIP_RELATIVE_STORE qword_store;
                int mov_hits, score;

                if (!ReadRipRelativeStore(ctx, pos, &store)) continue;
                if (store.IsQword || store.TargetRva != seci_rva) continue;

                // Qword store after the DWORD store
                BOOLEAN has_qword = FindNearbyQwordStore(ctx, pos, search_end, &qword_gap, &qword_store);
                mov_hits = CountSeCiMovs(ctx, pos, seci_rva, 300);

                score = 30;
                score += zero_score * 10;
                score += mov_hits;
                {
                    ULONG dist = pos - lea_file;
                    ULONG pen = dist / 32;
                    if (pen > 10) pen = 10;
                    score -= (int)pen;
                }
                if (has_qword) {
                    ULONG gap_capped = qword_gap < 16 ? qword_gap : 16;
                    score += 50 - (int)gap_capped;
                    if (IsWritableSectionIndex(ctx, qword_store.TargetSectionIndex)) score += 5;
                }
                if (store.Imm32 >= 0x40 && store.Imm32 <= 0x400) score += 5;
                if (store.Imm32 == SECI_FLAGS_EXPECTED) score += 10;
                if (has_zero_size) {
                    if (store.Imm32 == zero_size + 12) score += 10;
                    else if (store.Imm32 == zero_size || store.Imm32 == zero_size + 4 || store.Imm32 == zero_size + 8) score += 5;
                }

                if (score > best_score) {
                    best_score = score;
                    best_rva = seci_rva;
                }
            }
        }
    }

    if (best_score >= 0) return best_rva;
    return 0;
}

// Legacy anchor scan: looks for the byte sequence
//   C7 05 <disp32> 0x08 0x01 0x00 0x00  48 C7 05 ...
// which corresponds to a DWORD store of value 0x108 (SECI_FLAGS_EXPECTED)
// followed immediately by a QWORD store — a pattern stable across Win10/11.
// Walks backward from the anchor to find the LEA, then scores with CountSeCiMovs.
// Used as a fallback when the structural scan finds no candidate.
// Returns best seci_rva or 0 on failure.
static ULONG FindSeCiLegacy(PE_CONTEXT* ctx) {
    static const UCHAR kHead[2] = {0xC7, 0x05};
    static const UCHAR kTail[7] = {0x08, 0x01, 0x00, 0x00, 0x48, 0xC7, 0x05};
    ULONG best_rva = 0;
    LONG best_score = -1;
    ULONG pos;

    for (pos = 0; pos + 2 <= (ULONG)ctx->Size; ++pos) {
        ULONG tail_start, lea_file, search_start, search_end;
        RUNTIME_FUNCTION_INFO runtimeInfo;
        RIP_RELATIVE_STORE match_store;
        ULONG match_rva;
        LONG match_section;
        int k;

        if (ctx->Base[pos] != kHead[0] || ctx->Base[pos + 1] != kHead[1]) continue;
        tail_start = pos + 6;
        if (tail_start + 7 > (ULONG)ctx->Size) continue;

        for (k = 0; k < 7; k++) {
            if (ctx->Base[tail_start + k] != kTail[k]) goto next_pos;
        }

        if (!ReadRipRelativeStore(ctx, pos, &match_store)) goto next_pos;
        if (!FileOffsetToRva(ctx, pos, &match_rva, &match_section)) goto next_pos;

        if (FindRuntimeFunctionBounds(ctx, match_rva, &runtimeInfo)) {
            search_start = runtimeInfo.BeginOffset;
        } else {
            search_start = pos > 0x600 ? pos - 0x600 : 0;
        }
        search_end = pos; // scan backward to match_store position

        if (search_end < LEA_LEN || search_end <= search_start) goto next_pos;

        lea_file = search_end - LEA_LEN;
        for (;;) {
            if (IsRipRelativeLea(ctx, lea_file)) {
                ULONG lea_rva2, target_rva2, seci_rva;
                LONG lea_sec;
                LONG rel32;
                int score;

                if (FileOffsetToRva(ctx, lea_file, &lea_rva2, &lea_sec)) {
                    rel32 = *(PLONG)(ctx->Base + lea_file + 3);
                    target_rva2 = ComputeRelTargetRva(lea_rva2, LEA_LEN, rel32);
                    if (IsWritableData(ctx, target_rva2)) {
                        seci_rva = target_rva2 - STRUCT_OFFSET;
                        score = CountSeCiMovs(ctx, pos, seci_rva, 300);
                        if (seci_rva == match_store.TargetRva) score += 50;
                        if (score > best_score) {
                            best_score = score;
                            best_rva = seci_rva;
                        }
                    }
                }
            }
            if (lea_file == search_start) break;
            lea_file--;
        }

    next_pos:;
    }

    if (best_score >= 1) return best_rva;
    return 0;
}

// Main entry point for offline offset resolution.
// Reads ntoskrnl.exe from disk into a VM-allocated buffer, runs the structural
// scan first, then the legacy anchor scan as a fallback.  Whichever candidate
// has the higher CountSeCiMovs score is accepted.
//
// On success: config->Offset_SeCiCallbacks and config->Offset_SafeFunction
// are populated.  Returns TRUE if at least Offset_SeCiCallbacks was found.
// SafeFunction is located as the nearest exported stub at or before
// SeCiCallbacks in the .text section that is <= 0x20 bytes in size.
BOOLEAN FindKernelOffsetsLocally(PCONFIG_SETTINGS config) {
    UNICODE_STRING usPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS status;
    PE_CONTEXT ctx;
    BOOLEAN foundSeci = FALSE;
    BOOLEAN foundSafe = FALSE;
    WCHAR hexBuf[32];
    LONG bestScore = -1;
    ULONG bestSeCiRva = 0;

    memset_impl(&ctx, 0, sizeof(ctx));

    RtlInitUnicodeString(&usPath, L"\\SystemRoot\\System32\\ntoskrnl.exe");
    InitializeObjectAttributes(&oa, &usPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) return FALSE;

    FILE_STANDARD_INFORMATION fsi;
    status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(status)) { NtClose(hFile); return FALSE; }

    ctx.Size = (SIZE_T)fsi.EndOfFile.QuadPart;
    PVOID base = NULL;
    SIZE_T regionSize = ctx.Size;
    status = NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) { NtClose(hFile); return FALSE; }

    ctx.Base = (PUCHAR)base;
    status = NtReadFile(hFile, NULL, NULL, NULL, &iosb, ctx.Base, (ULONG)ctx.Size, NULL, NULL);
    NtClose(hFile);

    if (!NT_SUCCESS(status) || !ParsePe(&ctx)) {
        NtFreeVirtualMemory((HANDLE)-1, &base, &regionSize, MEM_RELEASE);
        return FALSE;
    }

    DisplayMessage(L"INFO: Scanning ntoskrnl.exe (Fast IDA)...\r\n");

    ULONG safeRva = FindExportRva(&ctx, "ZwFlushInstructionCache");
    if (safeRva) {
        config->Offset_SafeFunction = safeRva;
        foundSafe = TRUE;
        ULONGLONGToHexString(safeRva, hexBuf, TRUE);
        DisplayMessage(L"SUCCESS: SafeFunction found at "); DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
    }

    for (ULONG i = 0; i < ctx.SectionCount; i++) {
        ULONG sectionStart;
        ULONG sectionEnd;

        if (!(ctx.Sections[i].Characteristics & SCN_MEM_EXECUTE)) continue;
        sectionStart = ctx.Sections[i].RawPointer;
        sectionEnd = ctx.Sections[i].RawPointer + ctx.Sections[i].RawSize;
        if (sectionEnd > ctx.Size) {
            sectionEnd = (ULONG)ctx.Size;
        }
        if (sectionStart >= sectionEnd || sectionEnd - sectionStart < 10) {
            continue;
        }

        for (ULONG fileOffset = sectionStart; fileOffset + 10 <= sectionEnd; ++fileOffset) {
            RIP_RELATIVE_STORE store;
            RUNTIME_FUNCTION_INFO runtimeInfo;
            BOOLEAN hasRuntimeInfo;
            ULONG searchStart;
            ULONG searchEnd;
            ULONG qwordGap;
            RIP_RELATIVE_STORE qwordStore;

            if (ctx.Base[fileOffset] != 0xC7 || ctx.Base[fileOffset + 1] != 0x05) {
                continue;
            }
            if (fileOffset > 0 &&
                ctx.Base[fileOffset - 1] == 0x48 &&
                ctx.Base[fileOffset] == 0xC7 &&
                ctx.Base[fileOffset + 1] == 0x05) {
                continue;
            }
            if (!ReadRipRelativeStore(&ctx, fileOffset, &store)) {
                continue;
            }
            if (store.IsQword || !IsWritableSectionIndex(&ctx, store.TargetSectionIndex)) {
                continue;
            }
            if (!(store.Imm32 >= 0x40 && store.Imm32 <= 0x4000)) {
                continue;
            }

            hasRuntimeInfo = FindRuntimeFunctionBounds(&ctx, store.Rva, &runtimeInfo);
            if (hasRuntimeInfo) {
                searchStart = runtimeInfo.BeginOffset;
                searchEnd = MinUlong(runtimeInfo.EndOffsetExclusive, store.FileOffset + FAST_FORWARD_WINDOW);
            } else {
                searchStart = store.FileOffset > FAST_BACK_WINDOW ? store.FileOffset - FAST_BACK_WINDOW : 0;
                searchEnd = MinUlong((ULONG)ctx.Size, store.FileOffset + FAST_FORWARD_WINDOW);
            }

            if (!FindNearbyQwordStore(&ctx, store.FileOffset, searchEnd, &qwordGap, &qwordStore)) {
                continue;
            }

            if (store.FileOffset < LEA_LEN || store.FileOffset <= searchStart) {
                continue;
            }

            {
                ULONG leaTargetRva = store.TargetRva + STRUCT_OFFSET;
                ULONG leaFileOffset = store.FileOffset - LEA_LEN;

                for (;;) {
                    if (IsRipRelativeLea(&ctx, leaFileOffset)) {
                        ULONG leaRva;
                        LONG leaSectionIndex;
                        LONG rel32;
                        ULONG leaTarget;

                        if (FileOffsetToRva(&ctx, leaFileOffset, &leaRva, &leaSectionIndex)) {
                            rel32 = *(PLONG)(ctx.Base + leaFileOffset + 3);
                            leaTarget = ComputeRelTargetRva(leaRva, LEA_LEN, rel32);

                            if (leaTarget == leaTargetRva && IsWritableData(&ctx, leaTarget)) {
                                ULONG zeroSize;
                                BOOLEAN hasZeroSize;
                                int zeroScore = ScoreZeroingWindow(ctx.Base, ctx.Size, leaFileOffset, &zeroSize, &hasZeroSize);
                                if (zeroScore >= 2) {
                                    LONG score = 80;
                                    ULONG qwordDelta;
                                    ULONG distancePenalty;

                                    score += zeroScore * 12;
                                    score += 30 - (LONG)(qwordGap < 24 ? qwordGap : 24);

                                    distancePenalty = (store.FileOffset - leaFileOffset) / 32;
                                    if (distancePenalty > 12) {
                                        distancePenalty = 12;
                                    }
                                    score -= (LONG)distancePenalty;

                                    qwordDelta = qwordStore.TargetRva - store.TargetRva;
                                    if (qwordDelta > 0) {
                                        score += 8;
                                    }
                                    if (store.Imm32 == SECI_FLAGS_EXPECTED) {
                                        score += 12;
                                    }
                                    if (hasZeroSize) {
                                        if (qwordStore.TargetRva - leaTarget == zeroSize) {
                                            score += 18;
                                        }
                                        if (store.Imm32 == zeroSize + 12) {
                                            score += 18;
                                        } else if (store.Imm32 == zeroSize + 8 || store.Imm32 == zeroSize + 16) {
                                            score += 6;
                                        }
                                    }
                                    if (qwordDelta == store.Imm32 - 8) {
                                        score += 20;
                                    }

                                    if (score > bestScore) {
                                        bestScore = score;
                                        bestSeCiRva = store.TargetRva;
                                    }
                                }
                            }
                        }
                    }

                    if (leaFileOffset == searchStart) {
                        break;
                    }
                    leaFileOffset--;
                }
            }
        }
    }

    if (bestScore >= FAST_MIN_SCORE) {
        config->Offset_SeCiCallbacks = bestSeCiRva;
        config->Offset_Callback = 32;
        foundSeci = TRUE;
        ULONGLONGToHexString(bestSeCiRva, hexBuf, TRUE);
        DisplayMessage(L"SUCCESS: SeCiCallbacks found (Fast) at "); DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
    }

    if (!foundSeci) {
        ULONG structRva;
        DisplayMessage(L"INFO: Fast method insufficient, trying Structural scan...\r\n");
        structRva = FindSeCiStructural(&ctx);
        if (structRva != 0) {
            config->Offset_SeCiCallbacks = structRva;
            config->Offset_Callback = 32;
            foundSeci = TRUE;
            ULONGLONGToHexString(structRva, hexBuf, TRUE);
            DisplayMessage(L"SUCCESS: SeCiCallbacks found (Structural) at "); DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
        }
    }

    if (!foundSeci) {
        ULONG legacyRva;
        DisplayMessage(L"INFO: Structural method failed, trying Legacy anchor...\r\n");
        legacyRva = FindSeCiLegacy(&ctx);
        if (legacyRva != 0) {
            config->Offset_SeCiCallbacks = legacyRva;
            config->Offset_Callback = 32;
            foundSeci = TRUE;
            ULONGLONGToHexString(legacyRva, hexBuf, TRUE);
            DisplayMessage(L"SUCCESS: SeCiCallbacks found (Legacy) at "); DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
        }
    }

    NtFreeVirtualMemory((HANDLE)-1, &base, &regionSize, MEM_RELEASE);

    if (!foundSeci) DisplayMessage(L"WARNING: SeCiCallbacks NOT found by any method!\r\n");
    if (!foundSafe) DisplayMessage(L"WARNING: SafeFunction NOT found!\r\n");

    return (foundSeci && foundSafe);
}
