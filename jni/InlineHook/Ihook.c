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
    
    if(pstInlineHook == NULL)
    {
        LOGI("pstInlineHook is null");
        return bRet;
    }

    pstInlineHook->backUpLength = 8;
    
    memcpy(pstInlineHook->szbyBackupOpcodes, pstInlineHook->pHookAddr, pstInlineHook->backUpLength);

    for(int i=0;i<2;i++){
        currentOpcode += i;
        LOGI("Arm32 Opcode to fix %d : %x",i,*currentOpcode);
        LOGI("Fix length : %d",lengthFixArm32(*currentOpcode));
        pstInlineHook->backUpFixLengthList[i] = lengthFixArm32(*currentOpcode);
    }
    
    return true;
}

bool InitThumbHookInfo(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    int backUpPos = 0;
    uint16_t *currentOpcode = pstInlineHook->pHookAddr-1;
    int cnt = 0;
    int is_thumb32_count=0;

    for(int i=0;i<BACKUP_CODE_NUM_MAX;i++){
        pstInlineHook->backUpFixLengthList[i] = -1;
    }
    
    if(pstInlineHook == NULL)
    {
        LOGI("pstInlineHook is null");
        return bRet;
    }

    uint16_t *p11; 
    
    //判断最后由(pHookAddr-1)[10:11]组成的thumb命令是不是thumb32，
    //如果是的话就需要备份14byte或者10byte才能使得汇编指令不被截断。由于跳转指令在补nop的情况下也只需要10byte，
    //所以就取pstInlineHook->backUpLength为10

    for (int k=5;k>=0;k--){
        p11 = pstInlineHook->pHookAddr-1+k*2;
        LOGI("P11 : %x",*p11);
        if(isThumb32(*p11)){
            is_thumb32_count += 1;
        }else{
            break;
        }
    }

    LOGI("is_thumb32_count : %d",is_thumb32_count);
    
    if(is_thumb32_count%2==1)
    {
        LOGI("The last ins is thumb32. Length will be 10.");
        pstInlineHook->backUpLength = 10;
    }
    else{
        LOGI("The last ins is not thumb32. Length will be 12.");
        pstInlineHook->backUpLength = 12;
    }

    //修正：否则szbyBackupOpcodes会向后偏差1 byte
    memcpy(pstInlineHook->szbyBackupOpcodes, pstInlineHook->pHookAddr-1, pstInlineHook->backUpLength); 

    while(1)
    {
        LOGI("Hook Info Init");
        //int cnt=0;
        if(isThumb32(*currentOpcode))
        {
            LOGI("cnt %d thumb32",cnt);
            uint16_t *currentThumb32high = currentOpcode;
            uint16_t *currentThumb32low = currentOpcode+1;
            uint32_t instruction;
            int fixLength;

            instruction = (*currentThumb32high<<16) | *currentThumb32low;
            fixLength = lengthFixThumb32(instruction);
            LOGI("fixLength : %d",fixLength);
            pstInlineHook->backUpFixLengthList[cnt++] = 1; //说明是个thumb32
            pstInlineHook->backUpFixLengthList[cnt++] = fixLength - 1;
            backUpPos += 4;
        }
        else{
            LOGI("cnt %d thumb16",cnt);
            uint16_t instruction = *currentOpcode;
            int fixLength;
            fixLength = lengthFixThumb16(instruction);
            LOGI("fixLength : %d",fixLength);
            pstInlineHook->backUpFixLengthList[cnt++] = fixLength;
            backUpPos += 2;
        }

        if (backUpPos < pstInlineHook->backUpLength)
        {
            currentOpcode = pstInlineHook->pHookAddr -1 + sizeof(uint8_t)*backUpPos;
            LOGI("backUpPos : %d", backUpPos);
        }
        else{
            return true;
        }
    }
    
    return false;
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

//由于目标函数是thumb，所以_old_function_addr_s需要故意+1来切换成thumb模式，这样才能执行跳转之后的三条原始的thumb指令
bool BuildStubThumb(INLINE_HOOK_INFO* pstInlineHook) 
{
    bool bRet = false;
    
    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        
        void *p_shellcode_start_s = &_shellcode_start_s_thumb;
        void *p_shellcode_end_s = &_shellcode_end_s_thumb;
        void *p_hookstub_function_addr_s = &_hookstub_function_addr_s_thumb;
        void *p_old_function_addr_s = &_old_function_addr_s_thumb;

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
        pstInlineHook->ppOldFuncAddr  = pNewShellCode + (p_old_function_addr_s - p_shellcode_start_s); //打算对它+1
            
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
    bool bRet = false;
    while(1)
    {
        if(pCurAddress == NULL || pJumpAddress == NULL)
        {
            LOGI("address null.");
            break;
        }        
        //LDR PC, [PC, #-4]
        //addr
        //LDR PC, [PC, #-4]对应的机器码为：0xE51FF004
        //addr为要跳转的地址。该跳转指令范围为32位，对于32位系统来说即为全地址跳转。
        //缓存构造好的跳转指令（ARM下32位，两条指令只需要8个bytes）
        BYTE szLdrPCOpcodes[8] = {0x04, 0xF0, 0x1F, 0xE5};
        //将目的地址拷贝到跳转指令缓存位置
        memcpy(szLdrPCOpcodes + 4, &pJumpAddress, 4);
        
        //将构造好的跳转指令刷进去
        memcpy(pCurAddress, szLdrPCOpcodes, 8);
        cacheflush(*((uint32_t*)pCurAddress), 8, 0);
        
        bRet = true;
        break;
    }
    return bRet;
}

bool BuildThumbJumpCode(void *pCurAddress , void *pJumpAddress)
{
    bool bRet = false;
    while(1)
    {
        if(pCurAddress == NULL || pJumpAddress == NULL)
        {
            LOGI("address null.");
            break;
        }        
        //LDR PC, [PC, #0]
        //addr
        //LDR PC, [PC, #0]对应的thumb机器码为：0xf004f85f//arm下LDR PC, [PC, #-4]为0xE51FF004
        //addr为要跳转的地址。该跳转指令范围为32位，对于32位系统来说即为全地址跳转。
        //缓存构造好的跳转指令（ARM下32位，两条指令只需要8个bytes）
        //对于目标代码是thumb-2指令集来说，使用固定的8或者12byte备份是肯定有问题的！因为thumb16（2byte）和thumb32（4byte）是混合使用的
        //因此，当备份12byte时，如果目标是2+2+2+2+2+4，那就会把最后的那个thumb32截断。
        //当备份8byte时，如果目标是2+4+4，也会把最后的thumb32截断
        if (CLEAR_BIT0((uint32_t)pCurAddress) % 4 != 0) {
			//((uint16_t *) CLEAR_BIT0(pCurAddress))[i++] = 0xBF00;  // NOP
            BYTE szLdrPCOpcodes[12] = {0x00, 0xBF, 0xdF, 0xF8, 0x00, 0xF0};
            memcpy(szLdrPCOpcodes + 6, &pJumpAddress, 4);
            memcpy(pCurAddress, szLdrPCOpcodes, 10);
            cacheflush(*((uint32_t*)pCurAddress), 10, 0);
		}
        else{
            BYTE szLdrPCOpcodes[8] = {0xdF, 0xF8, 0x00, 0xF0};
            //将目的地址拷贝到跳转指令缓存位置
            memcpy(szLdrPCOpcodes + 4, &pJumpAddress, 4);
            memcpy(pCurAddress, szLdrPCOpcodes, 8);
            cacheflush(*((uint32_t*)pCurAddress), 8, 0);
        }

        
        
        //将构造好的跳转指令刷进去
        //memcpy(pCurAddress, szLdrPCOpcodes, 8); //这边需要参考ele7enxxh的代码，补上nop之类的
        //cacheflush(*((uint32_t*)pCurAddress), 8, 0);
        
        bRet = true;
        break;
    }
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

    fixOpcodes = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    
    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        
        //8个bytes存放原来的opcodes，另外8个bytes存放跳转回hook点下面的跳转指令
        void * pNewEntryForOldFunction = malloc(200);
        if(pNewEntryForOldFunction == NULL)
        {
            LOGI("new entry for old function malloc fail.");
            break;
        }

        pstInlineHook->pNewEntryForOldFunction = pNewEntryForOldFunction;
        
        if(ChangePageProperty(pNewEntryForOldFunction, 200) == false)
        {
            LOGI("change new entry page property fail.");
            break;
        }
        
        fixLength = fixPCOpcodeArm(fixOpcodes, pstInlineHook); //把第三部分的起始地址传过去
        memcpy(pNewEntryForOldFunction, fixOpcodes, fixLength);
        //memcpy(pNewEntryForOldFunction, pstInlineHook->szbyBackupOpcodes, 8);
        //填充跳转指令
        if(BuildArmJumpCode(pNewEntryForOldFunction + fixLength, pstInlineHook->pHookAddr + pstInlineHook->backUpLength) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        //填充shellcode里stub的回调地址
        *(pstInlineHook->ppOldFuncAddr) = pNewEntryForOldFunction;
        
        bRet = true;
        break;
    }
    
    return bRet;
}











bool BuildOldFunctionThumb(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    void *fixOpcodes;
    int fixLength;

    fixOpcodes = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    
    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        
        //12个bytes存放原来的thumb opcodes，另外8个bytes存放跳转回hook点下面的跳转指令
        void * pNewEntryForOldFunction = malloc(200);
        if(pNewEntryForOldFunction == NULL)
        {
            LOGI("new entry for old function malloc fail.");
            break;
        }

        pstInlineHook->pNewEntryForOldFunction = pNewEntryForOldFunction;
        
        if(ChangePageProperty(pstInlineHook->pNewEntryForOldFunction, 200) == false)
        {
            LOGI("change new entry page property fail.");
            break;
        }
        
        fixLength = fixPCOpcodeThumb(fixOpcodes, pstInlineHook); //修复PC相关指令
        //返回修复后opcode的指令长度，修复后的指令保存在fixOpcode中
        memcpy(pNewEntryForOldFunction, fixOpcodes, fixLength);
        //memcpy(pNewEntryForOldFunction, pstInlineHook->szbyBackupOpcodes, pstInlineHook->backUpLength);
        LOGI("pHookAddr : %x",pstInlineHook->pHookAddr);
        LOGI("backupLength : %x",pstInlineHook->backUpLength);
        //填充跳转指令
        if(BuildThumbJumpCode(pNewEntryForOldFunction + fixLength, pstInlineHook->pHookAddr + pstInlineHook->backUpLength) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        //填充shellcode里stub的回调地址
        *(pstInlineHook->ppOldFuncAddr) = pNewEntryForOldFunction;
        
        bRet = true;
        break;
    }
    
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
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        //修改原位置的页属性，保证可写
        if(ChangePageProperty(pstInlineHook->pHookAddr, 8) == false)
        {
            LOGI("change page property error.");
            break;
        }
        //填充跳转指令
        if(BuildArmJumpCode(pstInlineHook->pHookAddr, pstInlineHook->pStubShellCodeAddr) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        bRet = true;
        break;
    }
    
    return bRet;
}

bool RebuildHookTargetThumb(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    
    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        //修改原位置的页属性，保证可写
        if(ChangePageProperty(pstInlineHook->pHookAddr, 8) == false)
        {
            LOGI("change page property error.");
            break;
        }
        //填充跳转指令
        if(BuildThumbJumpCode(pstInlineHook->pHookAddr-1, pstInlineHook->pStubShellCodeAddr) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        bRet = true;
        break;
    }
    
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

        //LOGI("Init Arm HookInfo fail 1.");
        //设置ARM下inline hook的基础信息
        if(InitArmHookInfo(pstInlineHook) == false)
        {
            LOGI("Init Arm HookInfo fail.");
            break;
        }
        
        //LOGI("BuildStub fail 1.");
        //构造stub，功能是保存寄存器状态，同时跳转到目标函数，然后跳转回原函数
        //需要目标地址，返回stub地址，同时还有old指针给后续填充 
        if(BuildStub(pstInlineHook) == false)
        {
            LOGI("BuildStub fail.");
            break;
        }
        
        //LOGI("BuildOldFunction fail 1.");
        //负责重构原函数头，功能是修复指令，构造跳转回到原地址下
        //需要原函数地址
        if(BuildOldFunction(pstInlineHook) == false)
        {
            LOGI("BuildOldFunction fail.");
            break;
        }
        
        //LOGI("RebuildHookAddress fail 1.");
        //负责重写原函数头，功能是实现inline hook的最后一步，改写跳转
        //需要cacheflush，防止崩溃
        if(RebuildHookTarget(pstInlineHook) == false)
        {
            LOGI("RebuildHookAddress fail.");
            break;
        }
        bRet = true;
        break;
    }

    return bRet;
}

/**
 * Thumb16 Thumb32下的inlinehook
 * @param  pstInlineHook inlinehook信息
 * @return               inlinehook是否设置成功
 */
bool HookThumb(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    LOGI("HookThumb()");
    
    while(1)
    {
        //LOGI("pstInlineHook is null 1.");
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null.");
            break;
        }

        //LOGI("Init Thumb HookInfo fail 1.");
        //设置ARM下inline hook的基础信息
        if(InitThumbHookInfo(pstInlineHook) == false)
        {
            LOGI("Init Arm HookInfo fail.");
            break;
        }
        
        //LOGI("BuildStub fail 1.");
        //构造stub，功能是保存寄存器状态，同时跳转到目标函数，然后跳转回原函数
        //需要目标地址，返回stub地址，同时还有old指针给后续填充 
        if(BuildStubThumb(pstInlineHook) == false)
        {
            LOGI("BuildStub fail.");
            break;
        }
        
        //LOGI("BuildOldFunction fail 1.");
        //负责重构原函数头，功能是修复指令，构造跳转回到原地址下
        //需要原函数地址
        if(BuildOldFunctionThumb(pstInlineHook) == false)
        {
            LOGI("BuildOldFunction fail.");
            break;
        }
        
        //LOGI("RebuildHookAddress fail 1.");
        //负责重写原函数头，功能是实现inline hook的最后一步，改写跳转
        //需要cacheflush，防止崩溃
        if(RebuildHookTargetThumb(pstInlineHook) == false)
        {
            LOGI("RebuildHookAddress fail.");
            break;
        }
        bRet = true;
        break;
    }

    return bRet;
}
