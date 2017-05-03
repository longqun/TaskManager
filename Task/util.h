#include "info.h"
#ifndef _UTIL_H
#define _UTIL_H


void *getPspClidTable();
PHANDLE_TABLE*getHandleTable(PVOID PspClidTable);
void treatPspCildTable(PHANDLE_TABLE pHandleTable);



#endif // !_UTIL_H
