#include <stdio.h>
#include <pin.H>

void syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  printf("system-call: 0x%08x, arguments:", PIN_GetSyscallNumber(ctx, std));
  for (int i = 0; i < 4; ++i) {
    ADDRINT value = PIN_GetSyscallArgument(ctx, std, i);
    printf(" %d 0x%08x", value, value);
  }
}

void syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  ADDRINT return_value = PIN_GetSyscallReturn(ctx, std);
  printf(", return-value: %d 0x%08x\n", return_value, return_value);
}

int main(int argc, char *argv[])
{
  if (PIN_Init(argc, argv)) {
    printf("Usage: %s <binary> [arguments]\n");
    return 0;
  }

  PIN_AddSyscallEntryFunction(&syscall_entry, NULL);
  PIN_AddSyscallExitFunction(&syscall_exit, NULL);

  PIN_StartProgram();
  return 0;
}
