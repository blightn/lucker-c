#ifndef _MAIN_H_
#define _MAIN_H_

#include "defines.h"

#include "workers.h"
#include "flags.h"

#define PRINT_INTERVAL 15 // In seconds.

static BOOL IsSMTEnabled(PBOOL pEnabled);
static PCWSTR CoordinateTypeToString(COORDINATE_TYPE Type);

static BOOL ValidateFlagsCallback(FLAG_TYPE Type, INT Value);
static DWORD WINAPI ApplicationRecoveryCallback(PVOID pvParameter);
static BOOL WINAPI HandlerCallback(DWORD dwCtrlType);

#endif // _MAIN_H_
