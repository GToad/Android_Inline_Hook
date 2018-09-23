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
//#include <cacheflush.h>


#ifndef BYTE
#define BYTE unsigned char
#endif

#define OPCODEMAXLEN 24      //inline hook所需要的opcodes最大长度,arm64为20
#define BACKUP_CODE_NUM_MAX 6  //尽管备份原程序6条arm64指令。

#define LOG_TAG "GToad"
#define LOGI(fmt, args...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args);

#define PAGE_START(addr)	(~(PAGE_SIZE - 1) & (addr))
#define SET_BIT0(addr)		(addr | 1)
#define CLEAR_BIT0(addr)	(addr & 0xFFFFFFFE)
#define TEST_BIT0(addr)		(addr & 1)

#define ACTION_ENABLE	0
#define ACTION_DISABLE	1

//#define __flush_cache(c, n)        __builtin___clear_cache(reinterpret_cast<char *>(c), reinterpret_cast<char *>(c) + n)

extern unsigned long _shellcode_start_s;
extern unsigned long _shellcode_end_s;
extern unsigned long _hookstub_function_addr_s;
extern unsigned long _old_function_addr_s;


//hook点信息
typedef struct tagINLINEHOOKINFO{
    void *pHookAddr;                //hook的地址
    void *pStubShellCodeAddr;            //跳过去的shellcode stub的地址
    void (*onCallBack)(struct user_pt_regs *);       //回调函数，跳转过去的函数地址
    void ** ppOldFuncAddr;             //shellcode 中存放old function的地址
    BYTE szbyBackupOpcodes[OPCODEMAXLEN];    //原来的opcodes
    int backUpLength; //备份代码的长度，arm64模式下为20
    int backUpFixLengthList[BACKUP_CODE_NUM_MAX]; //保存
    uint64_t *pNewEntryForOldFunction;
} INLINE_HOOK_INFO;

bool ChangePageProperty(void *pAddress, size_t size);

extern void * GetModuleBaseAddr(pid_t pid, char* pszModuleName);

bool InitArmHookInfo(INLINE_HOOK_INFO* pstInlineHook);

bool BuildStub(INLINE_HOOK_INFO* pstInlineHook);

bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress);

bool BuildOldFunction(INLINE_HOOK_INFO* pstInlineHook);

bool RebuildHookTarget(INLINE_HOOK_INFO* pstInlineHook);

extern bool HookArm(INLINE_HOOK_INFO* pstInlineHook);

#endif

