#ifndef OFFSET_FINDER_H
#define OFFSET_FINDER_H

#include "BootBypass.h"

// Reads ntoskrnl.exe from disk and locates Offset_SeCiCallbacks and
// Offset_SafeFunction using a two-method heuristic scanner (structural LEA
// scan first, legacy anchor scan as fallback).  Populates config on success.
// Returns TRUE if at least Offset_SeCiCallbacks was found.
// Used when OffsetSource=SCAN or when INI offsets are missing (AUTO mode).
BOOLEAN FindKernelOffsetsLocally(PCONFIG_SETTINGS config);

#endif
