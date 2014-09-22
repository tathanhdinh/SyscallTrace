#include <Windows.h>
#include <winternl.h>
#include <tchar.h>

#include <iomanip>
#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <array>
#include <cstddef>
#include <type_traits>
#include <algorithm>
#include <sstream>
#include <type_traits>

/* exported functions */
std::string process_dependent_trace_name(unsigned int pid);

void parse_generic_syscall(std::wofstream &trace, std::string &syscall_name,
                           unsigned int args[], unsigned int return_code);

void parse_interesting_syscall(std::wofstream &trace, std::string &syscall_name,
                               unsigned int args[], unsigned int return_code);

bool is_verbose(std::string &syscall_name);

bool is_intersting(std::string &syscall_name);

/* local functions */
static std::wstring wbuffer_to_wstring(wchar_t *buffer, unsigned int length);

static std::wstring cbuffer_to_wstring(char *buffer, unsigned int length);

/* local variables */
static std::array<std::string, 16> verbose_syscalls =
{
  "NtFlushInstructionCache", "NtRequestWaitReplyPort", "NtQueryPerformanceCounter",
  "NtTestAlert", "NtContinue", "NtQueryDebugFilterState", "NtConnectPort"
  "NtQueryDefaultLocale", "NtDelayExecution", "NtWaitForMultipleObjects32",
  "NtAccessCheckAndAuditAlarm", "NtReplyWaitReceivePortEx", "NtQueryDefaultUILanguage",
  "NtQueryInstallUILanguage", "NtQueryDefaultLocale", "Unknow"
};

static std::array<std::string, 56> interesting_syscalls =
{
  "NtReadFile", "NtWriteFile", "NtCreateFile", "NtOpenFile", "NtClose",
  "NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection", "NtOpenSection",
  "NtOpenKey", "NtCreateKey", "NtSetValueKey", "NtQueryKey", "NtQueryValueKey",
  "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtDeviceIoControlFile",
  "NtCreateEvent", "NtWaitForSingleObject", "NtFlushBuffersFile", "NtQueryInformationFile",
  "NtQueryVolumeInformationFile", "NtSetInformationFile", "NtQueryDirectoryFile",
  "NtEnumerateKey", "NtOpenProcess", "NtCreateProcessEx", "NtReadVirtualMemory",
  "NtWriteVirtualMemory", "NtCreateThread", "NtResumeThread", "NtQueryInformationProcess",
  "NtQuerySection", "NtQueryInformationToken", "NtSetInformationProcess",
  "NtQueryAttributesFile", "NtSetEvent", "NtQueryEvent", "NtOpenEvent",
  "NtOpenThreadToken", "NtOpenThreadTokenEx", "NtSetInformationObject", "NtQueryVirtualMemory",
  "NtQueryInformationThread", "NtTerminateThread", "NtSetInformationThread"
  "NtCreateSemaphore", "NtReleaseSemaphore", "NtProtectVirtualMemory",
  "NtOpenProcessToken", "NtAdjustPrivilegesToken", "NtFsControlFile",
  "NtDuplicateToken", "NtOpenProcessTokenEx", "NtDuplicateObject",
  "NtQuerySystemInformation"
};

/* ============================================================================
* generate a trace file name depending on process id
* ========================================================================== */
std::string process_dependent_trace_name(unsigned int pid)
{
  std::stringstream ss;
  ss << std::dec << pid;

  std::string trace_name("strace_windows.");
  trace_name += ss.str(); trace_name += ".txt";
  return trace_name;
}

/* ============================================================================
* filter some verbose syscalls
* ========================================================================== */
bool is_verbose(std::string &syscall_name)
{
  if (std::find(verbose_syscalls.begin(), verbose_syscalls.end(), syscall_name)
      != verbose_syscalls.end()) return true;
  else return false;
}

/* ============================================================================
* filter some interesting syscalls
* ========================================================================== */
bool is_intersting(std::string &syscall_name)
{
  if (std::find(interesting_syscalls.begin(), interesting_syscalls.end(), syscall_name)
      != interesting_syscalls.end()) return true;
  else return false;
}

/* ============================================================================
* convert wchar_t* buffer to std::wstring
* ========================================================================== */
std::wstring wbuffer_to_wstring(wchar_t *buffer, unsigned int length)
{
  wchar_t *w_buffer = new wchar_t[length + 1]();
  ::wcsncpy(w_buffer, buffer, length);
  std::wstring result(w_buffer);

  delete[] w_buffer;
  return result;
}

/* ============================================================================
* convert char* buffer to std::wstring
* ========================================================================== */
std::wstring cbuffer_to_wstring(char *buffer, unsigned int length)
{
  char *c_buffer = new char[length + 1]();
  ::strncpy(c_buffer, buffer, length);
  std::string c_result(c_buffer);
  std::wstring result(c_result.begin(), c_result.end());

  delete[] c_buffer;
  return result;
}


/* ============================================================================
* parse the NtCreateFile syscall
* ========================================================================== */
void parse_args_NtCreateFile(std::wofstream &trace, unsigned int args[])
{
//  trace << L"NtCreateFile\t(";

  // get the output file handle
  PHANDLE hFileHandle = PHANDLE (args[0]);
  trace << L"FileHdl=>0x" << *hFileHandle;

  // get the input file path 
  POBJECT_ATTRIBUTES pObjAttrs = POBJECT_ATTRIBUTES (args[2]);
  trace << L", RootHdl<=0x" << pObjAttrs->RootDirectory;
  std::wstring file_path = wbuffer_to_wstring(pObjAttrs->ObjectName->Buffer,
                                              pObjAttrs->ObjectName->Length);
  trace << L", File<=" << file_path;

//  trace << L")\tRet=>" << return_code << std::endl;
}

/* ============================================================================
* parse the NtOpenFile syscall
* ========================================================================= */
void parse_args_NtOpenFile(std::wofstream &trace, unsigned int args[])
{
//  trace << L"NtOpenFile\t(";

  // get the output file handle
  PHANDLE hFileHandle = reinterpret_cast<PHANDLE>(args[0]);
  trace << L"FileHdl=>0x" << *hFileHandle;

  // get the input file path 
  POBJECT_ATTRIBUTES pObjAttrs = reinterpret_cast<POBJECT_ATTRIBUTES>(args[2]);
  trace << L", RootHdl<=0x" << pObjAttrs->RootDirectory;
  std::wstring file_path = wbuffer_to_wstring(pObjAttrs->ObjectName->Buffer,
                                              pObjAttrs->ObjectName->Length);
  trace << L", File<=" << file_path;

//  trace << L")\tRet=>" << return_code << std::endl;
}

/* ============================================================================
* parse the NtCreateSection syscall
* ========================================================================= */
void parse_args_NtCreateSection(std::wofstream &trace, unsigned int args[])
{
//  trace << L"NtCreateSection\t(";

  // get the output section handle
  PHANDLE pSectionHandle = reinterpret_cast<PHANDLE>(args[0]);
  trace << L"SecHdl=>0x" << *pSectionHandle;

  // get the input desired access
  /*trace << L", DesiredAccess<=";
  ACCESS_MASK desiredAccess = static_cast<ACCESS_MASK>(args[1]);
  switch (desiredAccess) {
  case SECTION_EXTEND_SIZE: trace << L"SECTION_EXTEND_SIZE"; break;
  case SECTION_MAP_EXECUTE: trace << L"SECTION_MAP_EXECUTE"; break;
  case SECTION_MAP_READ: trace << L"SECTION_MAP_READ"; break;
  case SECTION_MAP_WRITE: trace << L"SECTION_MAP_WRITE"; break;
  case SECTION_QUERY: trace << L"SECTION_QUERY"; break;
  case SECTION_ALL_ACCESS: trace << L"SECTION_ALL_ACCESS"; break;
  case GENERIC_READ: trace << L"GENERIC_READ"; break;
  case GENERIC_WRITE: trace << L"GENERIC_WRITE"; break;
  case GENERIC_EXECUTE: trace << L"GENERIC_EXECUTE"; break;
  case GENERIC_ALL: trace << L"GENERIC_ALL"; break;
  case READ_CONTROL: trace << L"STANDARD_RIGHTS_(READ,WRITE,EXECUTE)"; break;
  case STANDARD_RIGHTS_REQUIRED: trace << L"STANDARD_RIGHTS_REQUIRED"; break;
  case STANDARD_RIGHTS_ALL: trace << L"STANDARD_RIGHTS_ALL"; break;
  default: trace << L"Unknow access code: " << desiredAccess; break;
  }*/

  // get the input allocation attributes
  trace << L", AllocAttrs<=";
  ULONG allocAttrs = static_cast<ULONG>(args[5]);
  switch (allocAttrs) {
  case SEC_IMAGE: trace << L"SEC_IMAGE"; break;
  case SEC_FILE: trace << L"SEC_FILE"; break;
  case SEC_RESERVE: trace << L"SEC_RESERVE"; break;
  case SEC_COMMIT: trace << L"SEC_COMMIT"; break;
  case SEC_NOCACHE: trace << L"SEC_NOCACHE"; break;
  default: trace << "Unknow attributes code: " << allocAttrs; break;
  }

  // get the input mapped file handle
  HANDLE hFileHandle = reinterpret_cast<HANDLE>(args[6]);
  trace << L", FileHdl<=0x" << hFileHandle;

//  trace << L")\tRet=>" << return_code << std::endl;
}

/* ============================================================================
* parse the NtOpenSection syscall
* ========================================================================= */
void parse_args_NtOpenSection(std::wofstream &trace, unsigned int args[])
{
  // parse the output section handle
  PHANDLE pSectionHandle = reinterpret_cast<PHANDLE>(args[0]);
  trace << L"SecHdl=>0x" << *pSectionHandle;

  // parse the input file path
  POBJECT_ATTRIBUTES pObjAttrs = reinterpret_cast<POBJECT_ATTRIBUTES>(args[2]);
  trace << L", RootHdl<=0x" << pObjAttrs->RootDirectory;
  std::wstring file_path = wbuffer_to_wstring(pObjAttrs->ObjectName->Buffer,
                                              pObjAttrs->ObjectName->Length);
  trace << L", File<=" << file_path;
}


/* ============================================================================
* parse the NtMapViewOfSection
* ========================================================================== */
void parse_args_NtMapViewOfSection(std::wofstream &trace, unsigned int args[])
{
  // get the input section handle
  HANDLE hSectionHandle = reinterpret_cast<HANDLE>(args[0]);
  trace << L"SecHdl<=0x" << hSectionHandle;

  // get the input process handle
  HANDLE hProcessHandle = reinterpret_cast<HANDLE>(args[1]);
  trace << L", ProcHdl<=0x" << hProcessHandle;

  // get the output base address
  PVOID *pBaseAddress = reinterpret_cast<PVOID*>(args[2]);
  trace << L", BaseAddr<=0x" << *pBaseAddress;

  //// get the input commit size
  //SIZE_T lCommitSize = static_cast<SIZE_T>(arg_4);
  //trace << L"CommitSize<=0x" << lCommitSize;

  //// get the output section offset
  //HANDLE pSectionOffset = reinterpret_cast<HANDLE>(arg_5);
  //trace << L"SectionOffset=>0x" << *(reinterpret_cast<unsigned int*>(pSectionOffset));

//  trace << L")\tRet=>" << return_code << std::endl;
}

/* ============================================================================
* parse the NtUnMapViewOfSection
* ========================================================================= */
void parse_args_NtUnmapViewOfSection(std::wofstream &trace, unsigned int args[])
{
  HANDLE hProcessHandle = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ProcHdl<=0x" << hProcessHandle;

  PVOID pBaseAddress = reinterpret_cast<PVOID>(args[1]);
  trace << L", BaseAddr<=0x" << pBaseAddress;
}

/* ============================================================================
* parse the NtClose syscall
* ========================================================================= */
void parse_args_NtClose(std::wofstream &trace, unsigned int args[])
{
  // get the input file handle
  HANDLE hHandle = HANDLE (args[0]);
  trace << L"Hdl<=0x" << hHandle;
}

/* ============================================================================
* parse the NtWriteFile syscall
* ========================================================================= */
void parse_args_NtWriteFile(std::wofstream &trace, unsigned int args[])
{
  // get the input file handle
  HANDLE hFileHandle = reinterpret_cast<HANDLE>(args[0]);
  trace << L"FileHdl<=0x" << hFileHandle ;

  // get the input buffer address and length
  PVOID pBuffer = reinterpret_cast<PVOID>(args[5]);
  ULONG uLength = static_cast<ULONG>(args[6]);
  trace << L", BuffAddr<=0x" << pBuffer <<  L", ByteNum<=" << uLength;
}

/* ============================================================================
* parse the NtReadFile syscall
* ========================================================================= */
void parse_args_NtReadFile(std::wofstream &trace, unsigned int args[])
{
  // get the input file handle
  HANDLE hFileHandle = reinterpret_cast<HANDLE>(args[0]);
  trace << L"FileHdl<=0x" << hFileHandle;

  // get the output buffer address and length
  PVOID pBuffer = reinterpret_cast<PVOID>(args[5]);
  ULONG uLength = static_cast<ULONG>(args[6]);
  trace << L", BuffAddr<=0x" << pBuffer << L", ByteNum<=" << uLength;
}

/* ============================================================================
* parse the NtOpenKey
* ========================================================================== */
void parse_args_NtOpenKey(std::wofstream &trace, unsigned int args[])
{
  // parse the output key handle
  PHANDLE pKeyHandle = reinterpret_cast<PHANDLE>(args[0]);
  trace << L"KeyHdl=>0x" << *pKeyHandle;

  // parse the input key
  POBJECT_ATTRIBUTES pObjAttrs = reinterpret_cast<POBJECT_ATTRIBUTES>(args[2]);
  trace << L", RootHdl<=0x" << pObjAttrs->RootDirectory;
  std::wstring key = wbuffer_to_wstring(pObjAttrs->ObjectName->Buffer,
                                        pObjAttrs->ObjectName->Length);
  trace << L", Key<=" << key;
}

/* ============================================================================
* parse the NtCreateKey
* ========================================================================== */
void parse_args_NtCreateKey(std::wofstream &trace, unsigned int args[])
{
  // parse the output key handle
  PHANDLE pKeyHandle = reinterpret_cast<PHANDLE>(args[0]);
  trace << L"KeyHdl=>0x" << *pKeyHandle;

  // parse the input key
  POBJECT_ATTRIBUTES pObjAttrs = reinterpret_cast<POBJECT_ATTRIBUTES>(args[2]);
  trace << L", RootHdl<=0x" << pObjAttrs->RootDirectory;

  std::wstring key = wbuffer_to_wstring(pObjAttrs->ObjectName->Buffer,
                                        pObjAttrs->ObjectName->Length);
  trace << L", Key<=" << key;
}

/* ============================================================================
* parse the NtSetValueKey
* ========================================================================== */
void parse_args_NtSetValueKey(std::wofstream &trace, unsigned int args[])
{
  // parse the input key handle
  HANDLE hKeyHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"KeyHdl<=0x" << hKeyHdl;

  // parse the value name
  PUNICODE_STRING pUniStr = reinterpret_cast<PUNICODE_STRING>(args[1]);
  std::wstring value_name = wbuffer_to_wstring(pUniStr->Buffer, pUniStr->Length);
  trace << L", ValName<=" << value_name;

  // parse the value type
  trace << L", ValType<=";
  ULONG ulType = static_cast<ULONG>(args[3]);
  switch (ulType) {
  case REG_BINARY: trace << L"REG_BINARY"; break;
  case REG_DWORD: trace << L"REG_DWORD"; break;
  // case REG_DWORD_LITTLE_ENDIAN: trace << L"REG_DWORD_LITTLE_ENDIAN"; break;
  case REG_DWORD_BIG_ENDIAN: trace << L"REG_DWORD_BIG_ENDIAN"; break;
  case REG_EXPAND_SZ: trace << L"REG_EXPAND_SZ"; break;
  case REG_LINK: trace << L"REG_LINK"; break;
  case REG_MULTI_SZ: trace << L"REG_MULTI_SZ"; break;
  case REG_NONE: trace << L"REG_NONE"; break;
  case REG_SZ: trace << L"REG_SZ"; break;
  case REG_RESOURCE_LIST: trace << L"REG_RESOURCE_LIST"; break;
  case REG_RESOURCE_REQUIREMENTS_LIST: trace << L"REG_RESOURCE_REQUIREMENTS_LIST"; break;
  case REG_FULL_RESOURCE_DESCRIPTOR: trace << L"REG_FULL_RESOURCE_DESCRIPTOR"; break;
  }

  // parse the value entry data
  trace << L", ValEntry<=";
  PVOID pvEntryData = reinterpret_cast<PVOID>(args[4]);
  ULONG ulDataSize = static_cast<ULONG>(args[5]);
  if (ulType == REG_SZ) trace << wbuffer_to_wstring(reinterpret_cast<wchar_t*>(pvEntryData), ulDataSize);
  else trace << L"Not a string";
}


/* ============================================================================
* parse the NtQueryKey
* ========================================================================== */
void parse_args_NtQueryKey(std::wofstream &trace, unsigned int args[])
{
  // parse the input key handle
  HANDLE hKeyHandle = reinterpret_cast<HANDLE>(args[0]);
  trace << L"KeyHdl<=0x" << hKeyHandle;
}

/* ============================================================================
* parse the NtQueryValueKey
* ========================================================================== */
void parse_args_NtQueryValueKey(std::wofstream &trace, unsigned int args[])
{
  // parse the input key handle
  HANDLE hKeyHandle = reinterpret_cast<HANDLE>(args[0]);
  trace << L"KeyHdl<=0x" << hKeyHandle;

  // parse the input key
  PUNICODE_STRING pUniStr = reinterpret_cast<PUNICODE_STRING>(args[1]);
  std::wstring key = wbuffer_to_wstring(pUniStr->Buffer, pUniStr->Length);
  trace << L", Key<=" << key;
}

/* ============================================================================
* parse the NtAllocateVirtualMemory
* ========================================================================== */
void parse_args_NtAllocateVirtualMemory(std::wofstream &trace, unsigned int args[])
{
  // parse the input process handle
  HANDLE hProcHandle = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ProcHdl<=0x" << hProcHandle;

  // parse the output base address
  PVOID *pBaseAddr = reinterpret_cast<PVOID*>(args[1]);
  trace << L", BaseAddr=>0x" << *pBaseAddr;

  // parse the output region size
  PSIZE_T pRegSize = reinterpret_cast<PSIZE_T>(args[3]);
  trace << L", RegSize=>" << *pRegSize;
}

/* ============================================================================
* parse the NtFreeVirtualMemory
* ========================================================================== */
void parse_args_NtFreeVirtualMemory(std::wofstream &trace, unsigned int args[])
{
  // parse the input process handle
  HANDLE hProcHandle = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ProcHdl<=0x" << hProcHandle;

  // parse the output base address
  PVOID *pBaseAddr = reinterpret_cast<PVOID*>(args[1]);
  trace << L", BaseAddr=>0x" << *pBaseAddr;
}

/* ============================================================================
* parse the NtDuplicateObject
* ========================================================================== */
void parse_args_NtDuplicateObject(std::wofstream &trace, unsigned int args[])
{
  // parse the source process handle
  HANDLE hSrcProcHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"SrcProcHdl<=0x" << hSrcProcHdl;

  // parse the source handle
  HANDLE hSrcHdl = reinterpret_cast<HANDLE>(args[1]);
  trace << L", SrcHdl<=0x" << hSrcHdl;

  // parse the target process handle
  HANDLE hTarProcHdl = reinterpret_cast<HANDLE>(args[2]);
  trace << L", TarProcHdl<=0x" << hTarProcHdl;

  // parse the target handle
  PHANDLE pTarHdl = reinterpret_cast<PHANDLE>(args[3]);
  trace << L", TarHdl=>0x" << *pTarHdl;
}

/* ============================================================================
* parse the NtDeviceIoControlFile
* ========================================================================== */
void parse_args_NtDeviceIoControlFile(std::wofstream &trace, unsigned int args[])
{
  // parse the file handle
  HANDLE hFileHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"FileHdl<=0x" << hFileHdl;

  // parse the event handle
  HANDLE hEventHdl = reinterpret_cast<HANDLE>(args[1]);
  trace << L", EventHdl<=0x" << hEventHdl;

  // parse the control code
  ULONG uCtlCode = static_cast<ULONG>(args[5]);
  trace << L", CtlCode<=" << uCtlCode;
}

/* ============================================================================
* parse the NtCreateEvent
* ========================================================================== */
void parse_args_NtCreateEvent(std::wofstream &trace, unsigned int args[])
{
  // parse the event handle
  PHANDLE pEventHdl = reinterpret_cast<PHANDLE>(args[0]);
  trace << L"EventHdl=>0x" << *pEventHdl;

  // parse the desired access
  /*ACCESS_MASK accessMask = static_cast<ACCESS_MASK>(arg_1);
  trace << L"DesiredAccess=>" << accessMask;*/

  // parse the event name
  /*POBJECT_ATTRIBUTES pObjAttrs = reinterpret_cast<POBJECT_ATTRIBUTES>(args[2]);
  std::wstring eventName = buffer_to_wstring(pObjAttrs->ObjectName);
  trace << L", EventName=>" << eventName;*/
}

/* ============================================================================
* parse the NtOpenThreadToken
* ========================================================================== */
void parse_args_NtOpenThreadToken(std::wofstream &trace, unsigned int args[])
{
  // parse the thread handle
  HANDLE hThreadHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ThreadHdl<=0x" << hThreadHdl;

  // parse the OpenAsSelf
  trace << L", OpenAsSelf<=";
  BOOLEAN bOpenAsSelf = static_cast<BOOLEAN>(args[2]);
  if (bOpenAsSelf != 0) trace << L"True";
  else trace << L"False";
}

/* ============================================================================
* parse the NtOpenThreadTokenEx
* ========================================================================== */
void parse_args_NtOpenThreadTokenEx(std::wofstream &trace, unsigned int args[])
{
  // parse the thread handle
  HANDLE hThreadHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ThreadHdl<=0x" << hThreadHdl;

  // parse the OpenAsSelf
  trace << L", OpenAsSelf<=";
  BOOLEAN bOpenAsSelf = static_cast<BOOLEAN>(args[2]);
  if (bOpenAsSelf != 0) trace << L"True";
  else trace << L"False";
}

/* ============================================================================
* parse the NtWaitForSingleObject
* ========================================================================== */
void parse_args_NtWaitForSingleObject(std::wostream &trace, unsigned int args[])
{
  // parse the object handle
  HANDLE hObjHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ObjHdl<=0x" << hObjHdl;
}

/* ============================================================================
* parse the NtFlushBuffersFile
* ========================================================================== */
void parse_args_NtFlushBuffersFile(std::wofstream &trace, unsigned int args[])
{
  // parse the object handle
  HANDLE hObjHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"FileHdl<=0x" << hObjHdl;
}

/* ============================================================================
* parse the NtQueryInformationFile
* ========================================================================== */
void parse_args_NtQueryInformationFile(std::wofstream &trace, unsigned int args[])
{
  // parse the file handle
  HANDLE hFileHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"FileHdl<=0x" << hFileHdl;

  // parse the input file information class
  /*FILE_INFORMATION_CLASS eFileInfoClass = static_cast<FILE_INFORMATION_CLASS>(args[4]);
  trace << L", FileInfoClass<=" << eFileInfoClass;*/
}

/* ============================================================================
* parse the NtSetInformationFile
* ========================================================================== */
void parse_args_NtSetInformationFile(std::wofstream &trace, unsigned int args[])
{
  // parse the input file handle
  HANDLE hFileHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"FileHdl<=0x" << hFileHdl;

  // parse the input file information class
  /*FILE_INFORMATION_CLASS eFileInfoClass = static_cast<FILE_INFORMATION_CLASS>(args[4]);
  trace << L", FileInfoClass<=" << eFileInfoClass;*/
}

/* ============================================================================
* parse the NtQueryVolumeInformationFile
* ========================================================================== */
void parse_args_NtQueryVolumeInformationFile(std::wofstream &trace, unsigned int args[])
{
  // parse the input file handle
  HANDLE hFileHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"FileHdl<=0x" << hFileHdl;
}

/* ============================================================================
* parse the NtQueryDirectoryFile
* ========================================================================== */
void parse_args_NtQueryDirectoryFile(std::wofstream &trace, unsigned int args[])
{
  // parse the input file handle
  HANDLE hFileHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"FileHdl<=0x" << hFileHdl;
}

/* ============================================================================
* parse the NtEnumerateKey
* ========================================================================== */
void parse_args_NtEnumerateKey(std::wofstream &trace, unsigned int args[])
{
  // parse the input key handle
  HANDLE hKeyHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"KeyHdl<=0x" << hKeyHdl;

  // parse the input subkey index
  ULONG ulKeyIndex = static_cast<ULONG>(args[1]);
  trace << L", KeyIndex<=" << ulKeyIndex;
}

/* ============================================================================
* parse the NtOpenProcess
* ========================================================================== */
void parse_args_NtOpenProcess(std::wofstream &trace, unsigned int args[])
{
  // parse the output process handle
  PHANDLE pProcHandle = reinterpret_cast<PHANDLE>(args[0]);
  trace << L"ProcHdl=>0x" << *pProcHandle;

  // parse the access mask
  trace << L", DesiredAccess<=";
  ACCESS_MASK eAccessMask = static_cast<ACCESS_MASK>(args[1]);
  switch (eAccessMask) {
  case PROCESS_ALL_ACCESS: trace << L"PROCESS_ALL_ACCESS"; break;
  case PROCESS_CREATE_PROCESS: trace << L"PROCESS_CREATE_ACCESS"; break;
  case PROCESS_CREATE_THREAD: trace << L"PROCESS_CREATE_THREAD"; break;
  default: trace << "Unknow access code: " << eAccessMask; break;
  }

  // parse the cliend id
  trace << L", ProcId<=0x";
  PHANDLE pClientId = reinterpret_cast<PHANDLE>(args[3]);
  HANDLE hProcId = pClientId[0];
  trace << hProcId; 

  // parse the object atrributes
//  POBJECT_ATTRIBUTES pObjAttrs = reinterpret_cast<POBJECT_ATTRIBUTES>(args[2]);
//  trace << L", ObjName<=" << wbuffer_to_wstring(pObjAttrs->ObjectName->Buffer,
//                                                pObjAttrs->ObjectName->Length);
}

/* ============================================================================
* parse the NtCreateProcessEx
* ========================================================================== */
void parse_args_NtCreateProcessEx(std::wofstream &trace, unsigned int args[])
{
  // parse the output process handle
  PHANDLE pProcHandle = reinterpret_cast<PHANDLE>(args[0]);
  trace << L"ProcHdl=>0x" << *pProcHandle;
}

/* ============================================================================
* parse the NtReadVirtualMemory
* ========================================================================== */
void parse_args_NtReadVirtualMemory(std::wofstream &trace, unsigned int args[])
{
  // parse the input process handle
  HANDLE hProcHandle = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ProcHdl<=0x" << hProcHandle;

  // parse the base address
  PVOID pBaseAddr = reinterpret_cast<PVOID>(args[1]);
  trace << L", BaseAddr<=0x" << pBaseAddr;

  // parse the buffer address
  PVOID pBuffAddr = reinterpret_cast<PVOID>(args[2]);
  trace << L", BuffAddr<=0x" << pBuffAddr;

  // parse the requested byte
  ULONG ulByteNum = static_cast<ULONG>(args[3]);
  trace << L", ByteNum<=" << ulByteNum;
}

/* ============================================================================
* parse the NtWriteVirtualMemory
* ========================================================================== */
void parse_args_NtWriteVirtualMemory(std::wofstream &trace, unsigned int args[])
{
  // parse the input process handle
  HANDLE hProcHandle = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ProcHdl<=0x" << hProcHandle;

  // parse the base address
  PVOID pBaseAddr = reinterpret_cast<PVOID>(args[1]);
  trace << L", BaseAddr<=0x" << pBaseAddr;

  // parse the buffer address
  PVOID pBuffAddr = reinterpret_cast<PVOID>(args[2]);
  trace << L", BuffAddr<=0x" << pBuffAddr;

  // parse the requested byte
  ULONG ulByteNum = static_cast<ULONG>(args[3]);
  trace << L", ByteNum<=" << ulByteNum;
}

/* ============================================================================
* parse the NtCreateThread
* ========================================================================== */
void parse_args_NtCreateThread(std::wofstream &trace, unsigned int args[])
{
  // parse the output thread handle
  PHANDLE pThreadHdl = reinterpret_cast<PHANDLE>(args[0]);
  trace << L"ThreadHdl=>0x" << *pThreadHdl;

  // parse the input process handle
  HANDLE hProcHdl = reinterpret_cast<HANDLE>(args[3]);
  trace << L", ProcHdl<=0x" << hProcHdl;
}

/* ============================================================================
* parse the NtResumeThread
* ========================================================================== */
void parse_args_NtResumeThread(std::wofstream &trace, unsigned int args[])
{
  // parse the input thread handle
  HANDLE hThreadHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ThreadHdl<=0x" << hThreadHdl;
}

/* ============================================================================
* parse the NtQueryInformationProcess
* ========================================================================== */
void parse_args_NtQueryInformationProcess(std::wofstream &trace, unsigned int args[])
{
  // parse the input process handle
  HANDLE hProcHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ProcHdl<=0x" << hProcHdl;

  // parse the input process info class
  trace << L", InfoClass<=";
  PROCESSINFOCLASS eProcInfoClass = static_cast<PROCESSINFOCLASS>(args[1]);
  switch (eProcInfoClass) {
  case ProcessBasicInformation: trace << L"ProcessBasicInformation"; break;
  default: trace << L"Unknow class code: " << eProcInfoClass; break;
  }
}

/* ============================================================================
* parse the NtSetInformationProcess
* ========================================================================== */
void parse_args_NtSetInformationProcess(std::wofstream &trace, unsigned int args[])
{
  // parse the input process handle
  HANDLE hProcHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ProcHdl<=0x" << hProcHdl;

  // parse the input process info class
  trace << L", InfoClass<=";
  PROCESSINFOCLASS eProcInfoClass = static_cast<PROCESSINFOCLASS>(args[1]);
  switch (eProcInfoClass) {
  case ProcessBasicInformation: trace << L"ProcessBasicInformation"; break;
  default: trace << L"Unknow class code: " << eProcInfoClass; break;
  }
}

/* ============================================================================
* parse the NtQueryAttributesFile
* ========================================================================== */
void parse_args_NtQueryAttributesFile(std::wofstream &trace, unsigned int args[])
{
  // parse the file name
  POBJECT_ATTRIBUTES pObjAttrs = reinterpret_cast<POBJECT_ATTRIBUTES>(args[0]);
  trace << L"File<=" << wbuffer_to_wstring(pObjAttrs->ObjectName->Buffer,
                                           pObjAttrs->ObjectName->Length);
}

/* ============================================================================
* parse the NtQuerySection
* ========================================================================== */
void parse_args_NtQuerySection(std::wofstream &trace, unsigned int args[])
{
  // parse the input section handle
  HANDLE hSecHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"SecHdl<=0x" << hSecHdl;

  // parse the input section information class
  trace << L", InfoClass<=";
  switch (args[1]) {
  case 0: trace << L"SectionBasicInformation"; break;
  case 1: trace << L"SectionImageInformation"; break;
  default: trace<< L"Unknow class code: " << args[1]; break;
  }
}

/* ============================================================================
* parse the NtQueryInformationToken
* ========================================================================== */
void parse_args_NtQueryInformationToken(std::wofstream &trace, unsigned int args[])
{
  // parse the input token handle
  HANDLE hTokenHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"TokenHdl<=0x" << hTokenHdl;

  // parse the input info class
  trace << L", InfoClass<=";
  TOKEN_INFORMATION_CLASS eTokenInfoClass = static_cast<TOKEN_INFORMATION_CLASS>(args[1]);
  switch (eTokenInfoClass) {
  case TokenDefaultDacl: trace << L"TokenDefaultDacl"; break;
  case TokenGroups: trace << L"TokenGroups"; break;
  case TokenImpersonationLevel: trace << L"TokenImpersonationLevel"; break;
  case TokenOwner: trace << L"TokenOwner"; break;
  case TokenPrimaryGroup: trace << L"TokenPrimaryGroup"; break;
  case TokenPrivileges: trace << L"TokenPrivileges"; break;
  case TokenSessionId: trace << L"TokenSessionId"; break;
  case TokenSource: trace << L"TokenSource"; break;
  case TokenStatistics: trace << L"TokenStatistics"; break;
  case TokenType: trace << L"TokenType"; break;
  case TokenUser: trace << L"TokenUser"; break;
  default: trace << L"Unknow class code: " << eTokenInfoClass; break;
  }
}

/* ============================================================================
* parse the NtSetEvent
* ========================================================================== */
void parse_args_NtSetEvent(std::wofstream &trace, unsigned int args[])
{
  // parse the input event handle
  HANDLE hEventHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"EventHdl<=0x" << hEventHdl;
}

/* ============================================================================
* parse the NtQueryEvent
* ========================================================================== */
void parse_args_NtQueryEvent(std::wofstream &trace, unsigned int args[])
{
  // parse the input event handle
  HANDLE hEventHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"EventHdl<=0x" << hEventHdl;
}

/* ============================================================================
* parse the NtOpenEvent
* ========================================================================== */
void parse_args_NtOpenEvent(std::wofstream &trace, unsigned int args[])
{
  // parse the output event handle
  PHANDLE phEventHdl = reinterpret_cast<PHANDLE>(args[0]);
  trace << L"EventHdl=>0x" << *phEventHdl;

  // parse the desired access
  trace << L", DesiredAccess<=";
  ACCESS_MASK eDesiredAccess = static_cast<ACCESS_MASK>(args[1]);
  switch (eDesiredAccess) {
//  case EVENT_QUERY_STATE: trace << L"EVENT_QUERY_STATE"; break;
  case EVENT_MODIFY_STATE: trace << L"EVENT_MODIFY_STATE"; break;
  case EVENT_ALL_ACCESS: trace << L"EVENT_ALL_ACCESS"; break;
  default: trace << L"Unknow access code: " << eDesiredAccess; break;
  }

//  trace << L"DesiredAccess<=0x" << eDesiredAccess;
}

/* ============================================================================
* parse the NtCreateSemaphore
* ========================================================================== */
void parse_args_NtCreateSemaphore(std::wostream &trace, unsigned int args[])
{
  // parse the output semaphore handle
  PHANDLE phSemaphoreHdl = reinterpret_cast<PHANDLE>(args[0]);
  trace << L"SemHdl=>0x" << phSemaphoreHdl;

  // parse the input desired access
  trace << L", DesiredAccess<=";
  ACCESS_MASK eDesiredAccess = static_cast<ACCESS_MASK>(args[1]);
  switch (eDesiredAccess) {
  case SEMAPHORE_ALL_ACCESS: trace << L"SEMAPHORE_ALL_ACCESS"; break;
  case SEMAPHORE_MODIFY_STATE: trace << L"SEMAPHORE_MODIFY_STATE"; break;
  default: trace << L"Unknow access code: " << eDesiredAccess; break;
  }

  // parse the input semaphore name
//  POBJECT_ATTRIBUTES pObjAttrs = reinterpret_cast<POBJECT_ATTRIBUTES>(args[2]);
//  trace << L", Name<=" << wbuffer_to_wstring(pObjAttrs->ObjectName->Buffer,
//                                            pObjAttrs->ObjectName->Length);
}

/* ============================================================================
* parse the NtReleaseSemaphore
* ========================================================================== */
void parse_args_NtReleaseSemaphore(std::wostream &trace, unsigned int args[])
{
  // parse the input semaphore handle
  HANDLE hSemHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"SemHdl<=0x" << hSemHdl;

  // parse the count
  ULONG uReleaseCount = static_cast<ULONG>(args[1]);
  trace << L", Count<=" << uReleaseCount;
}

/* ============================================================================
* parse the NtSetInformationObject
* ========================================================================== */
void parse_args_NtSetInformationObject(std::wofstream &trace, unsigned int args[])
{
  // parse the input object handle
  HANDLE hObjHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ObjectHdl<=0x" << hObjHdl;
}

/* ============================================================================
* parse the NtQueryVirtualMemory
* ========================================================================== */
void parse_args_NtQueryVirtualMemory(std::wofstream &trace, unsigned int args[])
{
  // parse the input process handle
  HANDLE hProcHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ProcHdl<=0x" << hProcHdl;

  // parse the input base address
  PVOID hBaseAddr = reinterpret_cast<PVOID>(args[0]);
  trace << L", BaseAddr<=0x" << hBaseAddr;
}

/* ============================================================================
* parse the NtQueryInformationThread
* ========================================================================== */
void parse_args_NtQueryInformationThread(std::wofstream &trace, unsigned int args[])
{
  // parse the input thread handle
  HANDLE hThreadHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ThreadHdl<=0x" << hThreadHdl;

  // parse the thread info class
  trace << L", InfoClass<=";
  THREADINFOCLASS eThreadInfoClass = static_cast<THREADINFOCLASS>(args[1]);
  switch (eThreadInfoClass) {
  case ThreadIsIoPending: trace << L"ThreadIsIoPending"; break;
  default: trace << L"Unknow class code: " << eThreadInfoClass; break;
  }
}

/* ============================================================================
* parse the NtTerminateThread
* ========================================================================== */
void parse_args_NtTerminateThread(std::wofstream &trace, unsigned int args[])
{
  // parse the input thread handle
  HANDLE hThreadHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ThreadHdl<=0x" << hThreadHdl;
}

/* ============================================================================
* parse the NtSetInformationThread
* ========================================================================== */
void parse_args_NtSetInformationThread(std::wofstream &trace, unsigned int args[])
{
  // parse the input thread handle
  HANDLE hThreadHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ThreadHdl<=0x" << hThreadHdl;
}


/* ============================================================================
* parse the NtProtectVirtualMemory
* ========================================================================== */
void parse_args_NtProtectVirtualMemory(std::wofstream &trace, unsigned int args[])
{
  // parse the input process handle
  HANDLE hProcHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ProcHdl<=0x" << hProcHdl;

  // parse the output base address
  PVOID *pBaseAddr = reinterpret_cast<PVOID*>(args[1]);
  trace << L", BaseAddr=>0x" << *pBaseAddr;
}

/* ============================================================================
* parse the NtOpenProcessToken
* ========================================================================== */
void parse_args_NtOpenProcessToken(std::wofstream &trace, unsigned int args[])
{
  // parse the input process handle
  HANDLE hProcHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ProcHdl<=0x" << hProcHdl;

  // parse the output token handle
  PHANDLE pTokeHdl = reinterpret_cast<PHANDLE>(args[2]);
  trace << L", TokenHdl=>0x" << *pTokeHdl;
}

/* ============================================================================
* parse the NtAdjustPrivilegesToken
* ========================================================================== */
void parse_args_NtAdjustPrivilegesToken(std::wofstream &trace, unsigned int args[])
{
  // parse the input token handle
  HANDLE hTokenHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"TokenHdl<=0x" << hTokenHdl;
}

/* ============================================================================
* parse the NtFsControlFile
* ========================================================================== */
void parse_args_NtFsControlFile(std::wofstream &trace, unsigned int args[])
{
  // parse the input file handle
  HANDLE hFileHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"FileHdl<=0x" << hFileHdl;

  // parse the input event handle
  HANDLE hEventHdl = reinterpret_cast<HANDLE>(args[1]);
  trace << L", EventHdl<=0x" << hEventHdl;
}

/* ============================================================================
* parse the NtDuplicateToken
* ========================================================================== */
void parse_args_NtDuplicateToken(std::wofstream &trace, unsigned int args[])
{
  // parse the input token handle
  HANDLE hTokenHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"TokenHdl<=0x" << hTokenHdl;

  // parse the output token handle
  PHANDLE pNewTokenHdl = reinterpret_cast<PHANDLE>(args[5]);
  trace << L", NewTokenHdl=>0x" << *pNewTokenHdl;
}

/* ============================================================================
* parse the NtQuerySystemInformation
* ========================================================================== */
void parse_args_NtQuerySystemInformation(std::wofstream &trace, unsigned int args[])
{
  // parse the input system info class
  trace << "SysInfoClass<=";
  SYSTEM_INFORMATION_CLASS eSysInfoClass = static_cast<SYSTEM_INFORMATION_CLASS>(args[0]);
  switch (eSysInfoClass) {
  case SystemBasicInformation: trace << L"SystemBasicInformation"; break;
  case SystemProcessInformation: trace << L"SystemProcessInformation"; break;
  case SystemPerformanceInformation: trace << L"SystemPerformanceInformation"; break;
  case SystemTimeOfDayInformation: trace << L"SystemTimeOfDayInformation"; break;
  case SystemProcessorPerformanceInformation: trace << L"SystemProcessorPerformanceInformation"; break;
  case SystemInterruptInformation: trace << L"SystemInterruptInformation"; break;
  case SystemExceptionInformation: trace << L"SystemExceptionInformation"; break;
  case SystemRegistryQuotaInformation: trace << L"SystemRegistryQuotaInformation"; break;
  case SystemLookasideInformation: trace << L"SystemLookasideInformation"; break;
  default: trace << "Unknow class code: " << eSysInfoClass; break;
  }
}


/* ============================================================================
* parse the NtOpenProcessTokenEx
* ========================================================================== */
void parse_args_NtOpenProcessTokenEx(std::wofstream &trace, unsigned int args[])
{
  // parse the input process handle
  HANDLE hProcHdl = reinterpret_cast<HANDLE>(args[0]);
  trace << L"ProcHdl<=0x" << hProcHdl;

  // parse the output token handle
  PHANDLE pTokenHdl = reinterpret_cast<PHANDLE>(args[3]);
  trace << L", TokenHdl=>0x" << *pTokenHdl;
}

/* ============================================================================
* parse general syscalls
* ========================================================================= */
void parse_generic_syscall(std::wofstream &trace, std::string &syscall_name,
                           unsigned int args[], unsigned int return_code)
{
  std::wstring syscall_wname(syscall_name.begin(), syscall_name.end());
  trace << syscall_wname << L"\t(" << "0x" << reinterpret_cast<void*>(args[0])
      << L", 0x" << reinterpret_cast<void*>(args[1])
      << L", 0x" << reinterpret_cast<void*>(args[2])
      << L", 0x" << reinterpret_cast<void*>(args[3])
      << L", 0x" << reinterpret_cast<void*>(args[4])
      << L", 0x" << reinterpret_cast<void*>(args[5])
      << L")\tRet " << return_code << std::endl;
}

/* ============================================================================
* parse interesting syscalls
* ========================================================================== */
void parse_interesting_syscall(std::wofstream &trace, std::string& syscall_name,
                               unsigned int args[], unsigned int return_code)
{
  std::wstring syscall_wname(syscall_name.begin(), syscall_name.end());
  trace << syscall_wname << L"\t(";

  if (syscall_name == "NtReadFile")                 // 1
    parse_args_NtReadFile(trace, args);
  else if (syscall_name == "NtWriteFile")           // 2
    parse_args_NtWriteFile(trace, args);
  else if (syscall_name == "NtCreateFile")          // 3
    parse_args_NtCreateFile(trace, args);
  else if (syscall_name == "NtOpenFile")            // 4
    parse_args_NtOpenFile(trace, args);
  else if (syscall_name == "NtFlushBuffersFile")    // 5
    parse_args_NtFlushBuffersFile(trace, args);
  else if (syscall_name == "NtClose")               // 6
    parse_args_NtClose(trace, args);
  else if (syscall_name == "NtCreateSection")       // 7
    parse_args_NtCreateSection(trace, args);
  else if (syscall_name == "NtMapViewOfSection")    // 8
    parse_args_NtMapViewOfSection(trace, args);
  else if (syscall_name == "NtUnmapViewOfSection")  // 9
    parse_args_NtUnmapViewOfSection(trace, args);
  else if (syscall_name == "NtOpenSection")         // 10
    parse_args_NtOpenSection(trace, args);
  else if (syscall_name == "NtOpenKey")             // 11
    parse_args_NtOpenKey(trace, args);
  else if (syscall_name == "NtCreateKey")           // 12
    parse_args_NtCreateKey(trace, args);
  else if (syscall_name == "NtSetValueKey")         // 13
    parse_args_NtSetValueKey(trace, args);
  else if (syscall_name == "NtQueryKey")            // 14
    parse_args_NtQueryKey(trace, args);
  else if (syscall_name == "NtQueryValueKey")       // 15
    parse_args_NtQueryValueKey(trace, args);
  else if (syscall_name == "NtAllocateVirtualMemory")           // 16
    parse_args_NtAllocateVirtualMemory(trace, args);
  else if (syscall_name == "NtFreeVirtualMemory")               // 17
    parse_args_NtFreeVirtualMemory(trace, args);
  else if (syscall_name == "NtDeviceIoControlFile")             // 18
    parse_args_NtDeviceIoControlFile(trace, args);
  else if (syscall_name == "NtCreateEvent")                     // 19
    parse_args_NtCreateEvent(trace, args);
  else if (syscall_name == "NtWaitForSingleObject")             // 20
    parse_args_NtWaitForSingleObject(trace, args);
  else if (syscall_name == "NtQueryInformationFile")            // 21
    parse_args_NtQueryInformationFile(trace, args);
  else if (syscall_name == "NtQueryVolumeInformationFile")      // 22
    parse_args_NtQueryVolumeInformationFile(trace, args);
  else if (syscall_name == "NtSetInformationFile")              // 23
    parse_args_NtSetInformationFile(trace, args);
  else if (syscall_name == "NtQueryDirectoryFile")              // 24
    parse_args_NtQueryDirectoryFile(trace, args);
  else if (syscall_name == "NtEnumerateKey")                    // 25
    parse_args_NtEnumerateKey(trace, args);
  else if (syscall_name == "NtOpenProcess")          // 26
    parse_args_NtOpenProcess(trace, args);
  else if (syscall_name == "NtCreateProcessEx")      // 27
    parse_args_NtCreateProcessEx(trace, args);
  else if (syscall_name == "NtReadVirtualMemory")    // 28
    parse_args_NtReadVirtualMemory(trace, args);
  else if (syscall_name == "NtWriteVirtualMemory")   // 29
    parse_args_NtWriteVirtualMemory(trace, args);
  else if (syscall_name == "NtCreateThread")         // 30
    parse_args_NtCreateThread(trace, args);
  else if (syscall_name == "NtResumeThread")         // 31
    parse_args_NtResumeThread(trace, args);
  else if (syscall_name == "NtQueryInformationProcess")  // 32
    parse_args_NtQueryInformationProcess(trace, args);
  else if (syscall_name == "NtQuerySection")             // 33
    parse_args_NtQuerySection(trace, args);
  else if (syscall_name == "NtQueryInformationToken")     // 34
    parse_args_NtQueryInformationToken(trace, args);
  else if (syscall_name == "NtSetInformationProcess")     // 35
    parse_args_NtSetInformationProcess(trace, args);
  else if (syscall_name == "NtQueryAttributesFile")       // 36
    parse_args_NtQueryAttributesFile(trace, args);
  else if (syscall_name == "NtSetEvent")   // 37
    parse_args_NtSetEvent(trace, args);
  else if (syscall_name == "NtQueryEvent") // 38
    parse_args_NtQueryEvent(trace, args);
  else if (syscall_name == "NtOpenEvent")  // 39
    parse_args_NtOpenEvent(trace, args);
  else if (syscall_name == "NtOpenThreadToken")  // 40
    parse_args_NtOpenThreadToken(trace, args);
  else if (syscall_name == "NtSetInformationObject") // 41
    parse_args_NtSetInformationObject(trace, args);
  else if (syscall_name == "NtQueryVirtualMemory")   // 42
    parse_args_NtQueryVirtualMemory(trace, args);
  else if (syscall_name == "NtQueryInformationThread") // 43
    parse_args_NtQueryInformationThread(trace, args);
  else if (syscall_name == "NtTerminateThread")        // 44
    parse_args_NtTerminateThread(trace, args);
  else if (syscall_name == "NtCreateSemaphore")        // 45
    parse_args_NtCreateSemaphore(trace, args);
  else if (syscall_name == "NtReleaseSemaphore")       // 46
    parse_args_NtReleaseSemaphore(trace, args);
  else if (syscall_name == "NtOpenThreadTokenEx")      // 47
    parse_args_NtOpenThreadTokenEx(trace, args);
  else if (syscall_name == "NtProtectVirtualMemory")   // 48
    parse_args_NtProtectVirtualMemory(trace, args);
  else if (syscall_name == "NtOpenProcessToken")       // 49
    parse_args_NtOpenProcessToken(trace, args);
  else if (syscall_name == "NtAdjustPrivilegesToken")  // 50
    parse_args_NtAdjustPrivilegesToken(trace, args);
  else if (syscall_name == "NtFsControlFile")          // 51
    parse_args_NtFsControlFile(trace, args);
  else if (syscall_name == "NtDuplicateToken")         // 52
    parse_args_NtDuplicateToken(trace, args);
  else if (syscall_name == "NtSetInformationThread")   // 53
    parse_args_NtSetInformationThread(trace, args);
  else if (syscall_name == "NtOpenProcessTokenEx")     // 54
    parse_args_NtOpenProcessTokenEx(trace, args);
  else if (syscall_name == "NtDuplicateObject")        // 55
    parse_args_NtDuplicateObject(trace, args);
  else if (syscall_name == "NtQuerySystemInformation") // 56
    parse_args_NtQuerySystemInformation(trace, args);

  trace << L")\tRet=>" << return_code << std::endl;
}
