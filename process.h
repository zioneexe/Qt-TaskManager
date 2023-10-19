#ifndef PROCESS_H
#define PROCESS_H

#include "windows.h"
#include <QString>

class Process
{
public:
    Process(DWORD pid);
    bool operator==(const Process& other) const;

    QString Name;
    DWORD PID;
    DWORD PPID;
    QString Status;
    ULONGLONG CPUTime;
    QString userName;
    DWORD basePriority;
    DWORD_PTR affinity;
    DWORD handles;
    DWORD threads;
    SIZE_T workingSet;
    SIZE_T peakWorkingSet;
    SIZE_T commitSize;
    SIZE_T pagedPool;
    SIZE_T NPpool;
    DWORD pageFaults;
    DWORD userObjects;
};

#endif // PROCESS_H
