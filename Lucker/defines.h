#ifndef _DEFINES_H_
#define _DEFINES_H_

#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include <Shlwapi.h>
#include <strsafe.h>

#include <wchar.h>

#pragma comment(lib, "Shlwapi.lib")

#define SECTOMS(s)	((s) * 1000)
#define MINTOMS(m)	((m) * SECTOMS(60))

#define DATA_FOLDER L"Data"

typedef const BYTE* PCBYTE;
typedef const VOID* PCVOID;

#endif // _DEFINES_H_
