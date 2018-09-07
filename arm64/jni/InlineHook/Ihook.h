#ifndef _IHOOK_H
#define _IHOOK_H

#include <stdio.h>
#include <Android/log.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <stdbool.h>

#ifndef BYTE
#define BYTE unsigned char
#endif

#define OPCODEMAXLEN 12      //inline hook所需要的opcodes最大长度,arm为8，thumb为12/10（因为要补一个nop），所以这里取12，当arm的时候只memcpy 8btye就行了
#define BACKUP_CODE_NUM_MAX 10  //尽管备份指令最多的可能是thumb-2下的6条thumb16，但是为了保险起见选择了10。

#define LOG_TAG "GToad"
#define LOGI(fmt, args...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args);

#define PAGE_START(addr)	(~(PAGE_SIZE - 1) & (addr))
#define SET_BIT0(addr)		(addr | 1)
#define CLEAR_BIT0(addr)	(addr & 0xFFFFFFFE)
#define TEST_BIT0(addr)		(addr & 1)

#define ACTION_ENABLE	0
#define ACTION_DISABLE	1

extern unsigned long _shellcode_start_s;
extern unsigned long _shellcode_end_s;
extern unsigned long _hookstub_function_addr_s;
extern unsigned long _old_function_addr_s;
extern unsigned long _shellcode_start_s_thumb;
extern unsigned long _shellcode_end_s_thumb;
extern unsigned long _hookstub_function_addr_s_thumb;
extern unsigned long _old_function_addr_s_thumb;

//hook点信息
typedef struct tagINLINEHOOKINFO{
    void *pHookAddr;                //hook的地址
    void *pStubShellCodeAddr;            //跳过去的shellcode stub的地址
    void (*onCallBack)(struct pt_regs *);       //回调函数，跳转过去的函数地址
    void ** ppOldFuncAddr;             //shellcode 中存放old function的地址
    BYTE szbyBackupOpcodes[OPCODEMAXLEN];    //原来的opcodes
    int backUpLength; //备份代码的长度，arm模式下为8，thumb模式下为10或12
    int backUpFixLengthList[BACKUP_CODE_NUM_MAX]; //保存
    uint32_t *pNewEntryForOldFunction;
} INLINE_HOOK_INFO;

bool ChangePageProperty(void *pAddress, size_t size);

extern void * GetModuleBaseAddr(pid_t pid, char* pszModuleName);

bool InitArmHookInfo(INLINE_HOOK_INFO* pstInlineHook);

bool BuildStub(INLINE_HOOK_INFO* pstInlineHook);

bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress);

bool BuildOldFunction(INLINE_HOOK_INFO* pstInlineHook);

bool RebuildHookTarget(INLINE_HOOK_INFO* pstInlineHook);

extern bool HookArm(INLINE_HOOK_INFO* pstInlineHook);

extern bool HookThumb(INLINE_HOOK_INFO* pstInlineHook);

#endif

