/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2012 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */

/* a lot of modification */

/* strace_windows.cc */
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

#include <pin.H>

#include "syscall.h"

#pragma comment(lib, "MSVCRT.lib")

/* imported functions */
extern std::string process_dependent_trace_name(unsigned int pid);

extern std::vector< std::shared_ptr<syscall> > load_syscall_table(const std::string&);    // load the syscall table

extern std::string lookup_syscall_name(std::vector< std::shared_ptr<syscall> >&, int);
extern int lookup_syscall_number(std::vector< std::shared_ptr<syscall> > &syscall_table,
                                 std::string &syscall_name);

void parse_generic_syscall(std::wofstream &trace, std::string &syscall_name,
                           unsigned int args[], unsigned int return_code);

void parse_interesting_syscall(std::wofstream &trace, std::string &syscall_name,
                               unsigned int args[], unsigned int return_code);

bool is_verbose(std::string &syscall_name);

bool is_intersting(std::string &syscall_name);

/* global variables */
//std::ofstream trace;                                         // global trace file
std::wofstream wtrace;                                         // global trace file (unicode version)
//std::ofstream io_trace;                                      // file io trace file
std::wofstream wio_trace;                                      // file io trace file (unicode version)

ADDRINT syscall_number;                                        // syscall number
std::string syscall_name;                                      // syscall name
ADDRINT args[9];                                               // syscall arguments
ADDRINT return_code;                                           // syscall return code

unsigned int syscall_count;                                    // count the order of the invoked syscall

/* private variables */
static std::vector< std::shared_ptr<syscall> > syscall_table; // loaded syscall table

/* ============================================================================
* print the syscall number and the arguments. 
* ========================================================================= */
VOID sys_before()
{
  syscall_name = lookup_syscall_name(syscall_table, syscall_number);
}

/* ============================================================================
* print the return value of the syscall
* ========================================================================= */
VOID sys_after()
{
  if (!is_verbose(syscall_name)) {
    syscall_count++;

//    wtrace << std::setw(7) << syscall_count << L"\t";
//    parse_generic_syscall(wtrace, syscall_name, args, return_code);

    if (is_intersting(syscall_name)) {
      wtrace << std::setw(7) << syscall_count << L"\t";
      parse_interesting_syscall(wtrace, syscall_name, args, return_code);
    }
    else {
      wtrace << std::setw(7) << syscall_count << L"\t";
      parse_generic_syscall(wtrace, syscall_name, args, return_code);
    }
  }
}

/* ============================================================================
* log the syscall number and the arguments. 
* execute just before the syscall is invoked
* ========================================================================== */
VOID syscall_enter(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
  syscall_number = PIN_GetSyscallNumber(ctxt, std);

  // basic arguments
  args[0] = PIN_GetSyscallArgument(ctxt, std, 0); args[1] = PIN_GetSyscallArgument(ctxt, std, 1);
  args[2] = PIN_GetSyscallArgument(ctxt, std, 2); args[3] = PIN_GetSyscallArgument(ctxt, std, 3);
  args[4] = PIN_GetSyscallArgument(ctxt, std, 4); args[5] = PIN_GetSyscallArgument(ctxt, std, 5);

  // additional arguments
  args[6] = PIN_GetSyscallArgument(ctxt, std, 6); args[7] = PIN_GetSyscallArgument(ctxt, std, 6);
  args[8] = PIN_GetSyscallArgument(ctxt, std, 7);

  sys_before();
}

/* ============================================================================
* log the return value of the syscall
* execute just after the syscall returns
* ========================================================================== */
VOID syscall_exit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
  return_code = PIN_GetSyscallErrno(ctxt, std);
  sys_after();
}

/* ===========================================================================
* log the loaded image.
* called just before the image is loaded
* ========================================================================== */
VOID image_load(IMG img, VOID *v)
{
  //trace << "Load module: " << IMG_Name(img) << IMG_Id(img) << std::endl;
}

/* ============================================================================
* log the unloaded image
* called somewhere...
* ========================================================================== */
VOID image_unload(IMG img, VOID *v)
{
  //trace << "Unload module: " << IMG_Name(img) << std::endl;
}

/* ============================================================================
* log the newly created process
* called just before a new child process is created
* ========================================================================== */
BOOL before_creating_process(CHILD_PROCESS child_process, VOID *data)
{
  wtrace << L"New process is going to be created with id "
         << CHILD_PROCESS_GetId(child_process) << std::endl;
  return TRUE;
}

/* ============================================================================
* commence function
* ========================================================================== */
VOID start_tracing(VOID *data)
{
  std::string trace_name, io_trace_name;

  trace_name = process_dependent_trace_name(PIN_GetPid());
  wtrace.open(trace_name); //wio_trace.open(io_trace_name);

  // load syscall table
  syscall_table = load_syscall_table("syscall_table.txt");

  syscall_count = 0;
}

/* ============================================================================
* fini function
* ========================================================================== */
VOID fini(INT32 code, VOID *v)
{
  wtrace << "#eof" << std::endl;
//  wio_trace << "#eof" << std::endl;
  wtrace.close();
//  wio_trace.close();
}

/* ============================================================================
* main
* ========================================================================== */
int main(int argc, char *argv[])
{
  PIN_Init(argc, argv);

  PIN_AddApplicationStartFunction(start_tracing, 0);

  // add instrumental functions
  PIN_AddSyscallEntryFunction(syscall_enter, 0);
  PIN_AddSyscallExitFunction(syscall_exit, 0);
  /*IMG_AddInstrumentFunction(image_load, 0);
  IMG_AddUnloadFunction(image_unload, 0);*/
  PIN_AddFollowChildProcessFunction(before_creating_process, 0);

  PIN_AddFiniFunction(fini, 0);

  // now the control is passed to Pin
  PIN_StartProgram();

  // so the program never returns
  return 0;
}
