/* syscall_capture.cc */

/* ============================================================================
 * Capture invoked system calls of running process.
 * Reuse some codes of Jurriaan Bremer @skier_t at 
 * http://jbremer.org/malware-unpacking-level-pintool
 * ========================================================================= */

#include <pin.H>
namespace WINDOWS
{
#include <Windows.h>
}
#include <iostream>
#include <iomanip>
#include <fstream>

/* ============================================================================
 * command line switches
 * ========================================================================= */
KNOB<std::string> KnotOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", 
  "syscall_capture.out", "specify trace file name");

/* ============================================================================
 * help message
 * ========================================================================= */
INT32 Usage()
{
  std::cerr << "The Pin tool prints out the invoked system calls of running process";
  std::cerr << std::endl << std::endl;
  std::cerr << KNOB_BASE::StringKnobSummary();
  std::cerr << std::endl;
  return -1;
}

/* ============================================================================
 * Get invoked syscall name and arguments
 * ========================================================================= */
void syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  std::cout.setf(std::ios::right);
  std::cout << "0x" << std::setw(8) << std::setfill('0') << std::hex 
    << PIN_GetSyscallNumber(ctx, std) << std::endl; 
}

int main(int argc, char* argv[])
{
  if (PIN_Init(argc, argv)) {
    return Usage();
  }
  else {
    PIN_AddSyscallEntryFunction(&syscall_entry, NULL);
    PIN_StartProgram();
    return 0;
  }
}