#include "Ihook.h"
#include "fixPCOpcode.h"

#define ALIGN_PC(pc)	(pc & 0xFFFFFFFC)

/**
 * 修改页属性，改成可读可写可执行
 * @param   pAddress   需要修改属性起始地址
 * @param   size       需要修改页属性的长度，byte为单位
 * @return  bool       修改是否成功
 */
bool ChangePageProperty(void *pAddress, size_t size)
{
    bool bRet = false;
    
    if(pAddress == NULL)
    {
        LOGI("change page property error.");
        return bRet;
    }
    
    //计算包含的页数、对齐起始地址
    unsigned long ulPageSize = sysconf(_SC_PAGESIZE); //得到页的大小
    int iProtect = PROT_READ | PROT_WRITE | PROT_EXEC;
    unsigned long ulNewPageStartAddress = (unsigned long)(pAddress) & ~(ulPageSize - 1); //pAddress & 0x1111 0000 0000 0000
    long lPageCount = (size / ulPageSize) + 1;
    
    long l = 0;
    while(l < lPageCount)
    {
        //利用mprotect改页属性
        int iRet = mprotect((const void *)(ulNewPageStartAddress), ulPageSize, iProtect);
        if(-1 == iRet)
        {
            LOGI("mprotect error:%s", strerror(errno));
            return bRet;
        }
        l++; 
    }
    
    return true;
}

/**
 * 通过/proc/$pid/maps，获取模块基址
 * @param   pid                 模块所在进程pid，如果访问自身进程，可填小余0的值，如-1
 * @param   pszModuleName       模块名字
 * @return  void*               模块基址，错误则返回0
 */
void * GetModuleBaseAddr(pid_t pid, char* pszModuleName)
{
    FILE *pFileMaps = NULL;
    unsigned long ulBaseValue = 0;
    char szMapFilePath[256] = {0};
    char szFileLineBuffer[1024] = {0};
    LOGI("first fork(): I'am father pid=%d", getpid());

    LOGI("Pid is %d\n",pid);

    //pid判断，确定maps文件
    if (pid < 0)
    {
        snprintf(szMapFilePath, sizeof(szMapFilePath), "/proc/self/maps");
    }
    else
    {
        snprintf(szMapFilePath, sizeof(szMapFilePath),  "/proc/%d/maps", pid);
    }

    pFileMaps = fopen(szMapFilePath, "r");
    if (NULL == pFileMaps)
    {
        return (void *)ulBaseValue;
    }
    LOGI("%d",pFileMaps);

    LOGI("Get map.\n");

    //循环遍历maps文件，找到相应模块，截取地址信息
    while (fgets(szFileLineBuffer, sizeof(szFileLineBuffer), pFileMaps) != NULL)
    {
        //LOGI("%s\n",szFileLineBuffer);
        //LOGI("%s\n",pszModuleName);
        if (strstr(szFileLineBuffer, pszModuleName))
        {
            LOGI("%s\n",szFileLineBuffer);
            char *pszModuleAddress = strtok(szFileLineBuffer, "-");
            if (pszModuleAddress)
            {
                ulBaseValue = strtoul(pszModuleAddress, NULL, 16);

                if (ulBaseValue == 0x8000)
                    ulBaseValue = 0;

                break;
            }
        }
    }
    fclose(pFileMaps);
    return (void *)ulBaseValue;
}

/**
 * arm下inline hook基础信息备份（备份原先的opcodes）
 * @param  pstInlineHook inlinehook信息
 * @return               初始化信息是否成功
 */
bool InitArmHookInfo(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    uint32_t *currentOpcode = pstInlineHook->pHookAddr;

    for(int i=0;i<BACKUP_CODE_NUM_MAX;i++){
        pstInlineHook->backUpFixLengthList[i] = -1;
    }
    LOGI("pstInlineHook->szbyBackupOpcodes is at %x",pstInlineHook->szbyBackupOpcodes);

    
    if(pstInlineHook == NULL)
    {
        LOGI("pstInlineHook is null");
        return bRet;
    }

    pstInlineHook->backUpLength = 20;
    
    memcpy(pstInlineHook->szbyBackupOpcodes, pstInlineHook->pHookAddr, pstInlineHook->backUpLength);

    for(int i=0;i<5;i++){
        //currentOpcode += i; //GToad BUG
        LOGI("Arm64 Opcode to fix %d : %x",i,*currentOpcode);
        LOGI("Fix length : %d",lengthFixArm32(*currentOpcode));
        pstInlineHook->backUpFixLengthList[i] = lengthFixArm32(*currentOpcode);
        currentOpcode += 1; //GToad BUG
    }
    
    return true;
}

/**
 * 利用ihookstub.s中的shellcode构造桩，跳转到pstInlineHook->onCallBack函数后，回调老函数
 * @param  pstInlineHook inlinehook信息
 * @return               inlinehook桩是否构造成功
 */
bool BuildStub(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    
    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        
        void *p_shellcode_start_s = &_shellcode_start_s;
        void *p_shellcode_end_s = &_shellcode_end_s;
        void *p_hookstub_function_addr_s = &_hookstub_function_addr_s;
        void *p_old_function_addr_s = &_old_function_addr_s;

        size_t sShellCodeLength = p_shellcode_end_s - p_shellcode_start_s;
        //malloc一段新的stub代码
        void *pNewShellCode = malloc(sShellCodeLength);
        if(pNewShellCode == NULL)
        {
            LOGI("shell code malloc fail.");
            break;
        }
        memcpy(pNewShellCode, p_shellcode_start_s, sShellCodeLength);
        //更改stub代码页属性，改成可读可写可执行
        if(ChangePageProperty(pNewShellCode, sShellCodeLength) == false)
        {
            LOGI("change shell code page property fail.");
            break;
        }

        //设置跳转到外部stub函数去
        void **ppHookStubFunctionAddr = pNewShellCode + (p_hookstub_function_addr_s - p_shellcode_start_s);
        *ppHookStubFunctionAddr = pstInlineHook->onCallBack;
        
        //备份外部stub函数运行完后跳转的函数地址指针，用于填充老函数的新地址
        pstInlineHook->ppOldFuncAddr  = pNewShellCode + (p_old_function_addr_s - p_shellcode_start_s);
            
        //填充shellcode地址到hookinfo中，用于构造hook点位置的跳转指令
        pstInlineHook->pStubShellCodeAddr = pNewShellCode;

        bRet = true;
        break;
    }
    
    return bRet;
}


/**
 * 构造并填充ARM下32的跳转指令，需要外部保证可读可写，且pCurAddress至少8个bytes大小
 * @param  pCurAddress      当前地址，要构造跳转指令的位置
 * @param  pJumpAddress     目的地址，要从当前位置跳过去的地址
 * @return                  跳转指令是否构造成功
 */
bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress)
{
    LOGI("LIVE4.3.1");
    bool bRet = false;
    while(1)
    {
        LOGI("LIVE4.3.2");
        if(pCurAddress == NULL || pJumpAddress == NULL)
        {
            LOGI("address null.");
            break;
        }    
        LOGI("LIVE4.3.3");    
        //LDR PC, [PC, #-4]
        //addr
        //LDR PC, [PC, #-4]对应的机器码为：0xE51FF004
        //addr为要跳转的地址。该跳转指令范围为32位，对于32位系统来说即为全地址跳转。
        //缓存构造好的跳转指令（ARM下32位，两条指令只需要8个bytes）
        //BYTE szLdrPCOpcodes[8] = {0x04, 0xF0, 0x1F, 0xE5};

        //STP X1, X0, [SP, #-0x10]
        //LDR X0, 4
        //BR X0
        //ADDR(64)
        BYTE szLdrPCOpcodes[20] = {0xe1, 0x03, 0x3f, 0xa9, 0x40, 0x00, 0x00, 0x58, 0x00, 0x00, 0x1f, 0xd6};
        //将目的地址拷贝到跳转指令缓存位置
        memcpy(szLdrPCOpcodes + 12, &pJumpAddress, 8);
        LOGI("LIVE4.3.4");
        
        //将构造好的跳转指令刷进去
        memcpy(pCurAddress, szLdrPCOpcodes, 20);
        LOGI("LIVE4.3.5");
        //__flush_cache(*((uint32_t*)pCurAddress), 20);
        //__builtin___clear_cache (*((uint64_t*)pCurAddress), *((uint64_t*)(pCurAddress+20)));
        //cacheflush(*((uint32_t*)pCurAddress), 20, 0);
        LOGI("LIVE4.3.6");
        bRet = true;
        break;
    }
    LOGI("LIVE4.3.7");
    return bRet;
}


/**
 * 构造被inline hook的函数头，还原原函数头+增加跳转
 * 仅是拷贝跳转即可，同时填充stub shellcode中的oldfunction地址及hookinfo里面的old函数地址
 * 这个实现没有指令修复功能，即是HOOK的位置指令不能涉及PC等需要重定向指令
 * @param  pstInlineHook inlinehook信息
 * @return               原函数构造是否成功
 */
bool BuildOldFunction(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    void *fixOpcodes;
    int fixLength;
    LOGI("LIVE3.1");

    fixOpcodes = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    LOGI("LIVE3.2");
    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        LOGI("LIVE3.3");
        
        //8个bytes存放原来的opcodes，另外8个bytes存放跳转回hook点下面的跳转指令
        void * pNewEntryForOldFunction = malloc(200);
        if(pNewEntryForOldFunction == NULL)
        {
            LOGI("new entry for old function malloc fail.");
            break;
        }
        LOGI("LIVE3.4");

        pstInlineHook->pNewEntryForOldFunction = pNewEntryForOldFunction;
        LOGI("%x",pNewEntryForOldFunction);
        
        if(ChangePageProperty(pNewEntryForOldFunction, 200) == false)
        {
            LOGI("change new entry page property fail.");
            break;
        }
        LOGI("LIVE3.5");
        
        fixLength = fixPCOpcodeArm(fixOpcodes, pstInlineHook); //把第三部分的起始地址传过去
        memcpy(pNewEntryForOldFunction, fixOpcodes, fixLength);
        LOGI("LIVE3.6");
        //memcpy(pNewEntryForOldFunction, pstInlineHook->szbyBackupOpcodes, 8);
        //填充跳转指令
        if(BuildArmJumpCode(pNewEntryForOldFunction + fixLength, pstInlineHook->pHookAddr + pstInlineHook->backUpLength) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        LOGI("LIVE3.7");
        //填充shellcode里stub的回调地址
        *(pstInlineHook->ppOldFuncAddr) = pNewEntryForOldFunction;
        LOGI("LIVE3.8");
        
        bRet = true;
        break;
    }
    LOGI("LIVE3.9");
    
    return bRet;
}


    
/**
 * 在要HOOK的位置，构造跳转，跳转到shellcode stub中
 * @param  pstInlineHook inlinehook信息
 * @return               原地跳转指令是否构造成功
 */
bool RebuildHookTarget(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    
    while(1)
    {
        LOGI("LIVE4.1");
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        LOGI("LIVE4.2");
        //修改原位置的页属性，保证可写
        if(ChangePageProperty(pstInlineHook->pHookAddr, 8) == false)
        {
            LOGI("change page property error.");
            break;
        }
        LOGI("LIVE4.3");
        //填充跳转指令
        if(BuildArmJumpCode(pstInlineHook->pHookAddr, pstInlineHook->pStubShellCodeAddr) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        LOGI("LIVE4.4");
        bRet = true;
        break;
    }
    LOGI("LIVE4.5");
    
    return bRet;
}


/**
 * ARM下的inlinehook
 * @param  pstInlineHook inlinehook信息
 * @return               inlinehook是否设置成功
 */
bool HookArm(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    LOGI("HookArm()");
    
    while(1)
    {
        //LOGI("pstInlineHook is null 1.");
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null.");
            break;
        }
        LOGI("LIVE1");

        //LOGI("Init Arm HookInfo fail 1.");
        //第零步，设置ARM下inline hook的基础信息
        if(InitArmHookInfo(pstInlineHook) == false)
        {
            LOGI("Init Arm HookInfo fail.");
            break;
        }
        LOGI("LIVE2");
        
        //LOGI("BuildStub fail 1.");
        //第二步，构造stub，功能是保存寄存器状态，同时跳转到目标函数，然后跳转回原函数
        //需要目标地址，返回stub地址，同时还有old指针给后续填充 
        if(BuildStub(pstInlineHook) == false)
        {
            LOGI("BuildStub fail.");
            break;
        }
        LOGI("LIVE3");
        
        //LOGI("BuildOldFunction fail 1.");
        //第四步，负责重构原函数头，功能是修复指令，构造跳转回到原地址下
        //需要原函数地址
        
        if(BuildOldFunction(pstInlineHook) == false)
        {
            LOGI("BuildOldFunction fail.");
            break;
        }
        LOGI("LIVE4");
        
        //LOGI("RebuildHookAddress fail 1.");
        //第一步，负责重写原函数头，功能是实现inline hook的最后一步，改写跳转
        //需要cacheflush，防止崩溃
        if(RebuildHookTarget(pstInlineHook) == false)
        {
            LOGI("RebuildHookAddress fail.");
            break;
        }
        LOGI("LIVE5");
        
        bRet = true;
        break;
    }
    LOGI("LIVE6");

    return bRet;
}


