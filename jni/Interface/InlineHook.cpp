#include <vector>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGE_START(addr)	(~(PAGE_SIZE - 1) & (addr))
#define SET_BIT0(addr)		(addr | 1)
#define CLEAR_BIT0(addr)	(addr & 0xFFFFFFFE)
#define TEST_BIT0(addr)		(addr & 1)

#define ACTION_ENABLE	0
#define ACTION_DISABLE	1

extern "C"
{
    #include "Ihook.h"
}

void ModifyIBored() __attribute__((constructor));
void before_main() __attribute__((constructor));

typedef std::vector<INLINE_HOOK_INFO*> InlineHookInfoPVec;
static InlineHookInfoPVec gs_vecInlineHookInfo;     //管理HOOK点

void before_main() {
    LOGI("Hook is auto loaded!\n");
}

/**
 * 对外inline hook接口，负责管理inline hook信息
 * @param  pHookAddr     要hook的地址
 * @param  onCallBack    要插入的回调函数
 * @return               inlinehook是否设置成功（已经设置过，重复设置返回false）
 */
bool InlineHook(void *pHookAddr, void (*onCallBack)(struct pt_regs *))
{
    bool bRet = false;
    LOGI("InlineHook");

    if(pHookAddr == NULL || onCallBack == NULL)
    {
        return bRet;
    }

    INLINE_HOOK_INFO* pstInlineHook = new INLINE_HOOK_INFO();
    pstInlineHook->pHookAddr = pHookAddr;
    pstInlineHook->onCallBack = onCallBack;

    //DEMO只很对ARM指令进行演示，更通用这里需要判断区分THUMB等指令
    if(TEST_BIT0((uint32_t)pstInlineHook->pHookAddr)){ //thumb mode
        LOGI("HookThumb Start.");
        if(HookThumb(pstInlineHook) == false)
        {
            LOGI("HookThumb fail.");
            delete pstInlineHook;
            return bRet;
        }
    }
    else{   
                                                 //arm mode
        if(HookArm(pstInlineHook) == false)
        {
            LOGI("HookArm fail.");
            delete pstInlineHook;
            return bRet;
        }
    }
    
    gs_vecInlineHookInfo.push_back(pstInlineHook);
    return true;
}

/**
 * 对外接口，用于取消inline hook
 * @param  pHookAddr 要取消inline hook的位置
 * @return           是否取消成功（不存在返回取消失败）
 */
bool UnInlineHook(void *pHookAddr)
{
    bool bRet = false;

    if(pHookAddr == NULL)
    {
        return bRet;
    }

    InlineHookInfoPVec::iterator itr = gs_vecInlineHookInfo.begin();
    InlineHookInfoPVec::iterator itrend = gs_vecInlineHookInfo.end();

    for (; itr != itrend; ++itr)
    {
        if (pHookAddr == (*itr)->pHookAddr)
        {
            INLINE_HOOK_INFO* pTargetInlineHookInfo = (*itr);

            gs_vecInlineHookInfo.erase(itr);
            if(pTargetInlineHookInfo->pStubShellCodeAddr != NULL)
            {
                delete pTargetInlineHookInfo->pStubShellCodeAddr;
            }
            if(pTargetInlineHookInfo->ppOldFuncAddr)
            {
                delete *(pTargetInlineHookInfo->ppOldFuncAddr);
            }
            delete pTargetInlineHookInfo;
            bRet = true;
        }
    }

    return bRet;
}

/**
 * 用户自定义的stub函数，嵌入在hook点中，可直接操作寄存器等改变游戏逻辑操作
 * 这里将R0寄存器锁定为0x333，一个远大于30的值
 * @param regs 寄存器结构，保存寄存器当前hook点的寄存器信息
 */
void EvilHookStubFunctionForIBored(pt_regs *regs) //参数regs就是指向栈上的一个数据结构，由第二部分的mov r0, sp所传递。
{
    LOGI("In Evil Hook Stub.");
    //regs->uregs[2] = 0x333; //regs->uregs[0]=0x333
    regs->uregs[0]=0x333;
}

/**
 * 针对IBored应用，通过inline hook改变游戏逻辑的测试函数
 */
void ModifyIBored()
{
    LOGI("In IHook's ModifyIBored.");

    /*
    //hellojni arm32 hook
    int target_offset = 0xf70; //想Hook的目标在目标so中的偏移
    bool is_target_thumb = false; //目标是否是thumb模式？
    void* pModuleBaseAddr = GetModuleBaseAddr(-1, "libhellojni.so"); //目标so的名称
    */

    //inline hook test3 thumb-2 hook
    int target_offset = 0x43b8; //*想Hook的目标在目标so中的偏移*
    bool is_target_thumb = true; //*目标是否是thumb模式？*
    void* pModuleBaseAddr = GetModuleBaseAddr(-1, "libnative-lib.so"); //目标so的名称

    if(pModuleBaseAddr == 0)
    {
        LOGI("get module base error.");
        return;
    }
    
    uint32_t uiHookAddr = (uint32_t)pModuleBaseAddr + target_offset; //真实Hook的内存地址

    if(is_target_thumb){ //之所以人来判断那是因为Native Hook之前肯定是要逆向分析一下的，那时候就能知道是哪种模式。而且自动识别arm和thumb比较麻烦。
        uiHookAddr++;
        LOGI("uiHookAddr is %X in thumb mode", uiHookAddr);
    }
    else{
        LOGI("uiHookAddr is %X in arm mode", uiHookAddr);
    }
    
    InlineHook((void*)(uiHookAddr), EvilHookStubFunctionForIBored); //*第二个参数就是Hook想要插入的功能处理函数*
}