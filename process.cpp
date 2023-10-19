#include "process.h"

Process::Process(DWORD pid) {}

bool Process::operator==(const Process& other) const {
    return this->PID == other.PID;
}
