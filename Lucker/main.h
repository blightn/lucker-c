#ifndef _MAIN_H_
#define _MAIN_H_

#include "defines.h" // ���� �� ������ ���� ��������� � "Windows.h", ����� �� ����������� WIN32_LEAN_AND_MEAN.

#include "workers.h"

#define PRINT_INTERVAL 15

static DWORD WINAPI ApplicationRecoveryCallback(PVOID pvParameter);
static BOOL WINAPI HandlerRoutine(DWORD dwCtrlType);
static BOOL IsSMTEnabled(PBOOL pEnabled);

#endif // _MAIN_H_
