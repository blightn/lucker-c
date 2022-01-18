#ifndef _MAIN_H_
#define _MAIN_H_

#include "defines.h" // Выше не должно быть включений с "Windows.h", чтобы не перекрывать WIN32_LEAN_AND_MEAN.

#include "workers.h"

#define PRINT_INTERVAL 15

static DWORD WINAPI ApplicationRecoveryCallback(PVOID pvParameter);
static BOOL WINAPI HandlerRoutine(DWORD dwCtrlType);
static BOOL IsSMTEnabled(PBOOL pEnabled);

#endif // _MAIN_H_
