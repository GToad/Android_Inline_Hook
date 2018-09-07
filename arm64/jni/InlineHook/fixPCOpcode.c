#include "fixPCOpcode.h"

//这里的代码建议看文章：《Android Inline Hook中的指令修复详解》（https://gtoad.github.io/2018/07/13/Android-Inline-Hook-Fix/）

enum INSTRUCTION_TYPE {
	// B <label>
	B1_THUMB16,
    // B <label>
    B1_BEQ_THUMB16,
    // B <label>
    B1_BNE_THUMB16,
    // B <label>
    B1_BCS_THUMB16,
    // B <label>
    B1_BCC_THUMB16,
    // B <label>
    B1_BMI_THUMB16,
    // B <label>
    B1_BPL_THUMB16,
    // B <label>
    B1_BVS_THUMB16,
    // B <label>
    B1_BVC_THUMB16,
    // B <label>
    B1_BHI_THUMB16,
    // B <label>
    B1_BLS_THUMB16,
    // B <label>
    B1_BGE_THUMB16,
    // B <label>
    B1_BLT_THUMB16,
    // B <label>
    B1_BGT_THUMB16,
    // B <label>
    B1_BLE_THUMB16,
	// B <label>
	B2_THUMB16,
	// BX PC
	BX_THUMB16,
	// ADD <Rdn>, PC (Rd != PC, Rn != PC) 在对ADD进行修正时，采用了替换PC为Rr的方法，当Rd也为PC时，由于之前更改了Rr的值，可能会影响跳转后的正常功能。
	ADD_THUMB16,
	// MOV Rd, PC
	MOV_THUMB16,
	// ADR Rd, <label>
	ADR_THUMB16,
	// LDR Rt, <label>
	LDR_THUMB16,

	// CB{N}Z <Rn>, <label>
	CB_THUMB16,


	// BLX <label>
	BLX_THUMB32,
	// BL <label>
	BL_THUMB32,
	// B.W <label>
	B1_THUMB32,
    // B.W <label>
    B1_BEQ_THUMB32,
    // B.W <label>
    B1_BNE_THUMB32,
    // B.W <label>
    B1_BCS_THUMB32,
    // B.W <label>
    B1_BCC_THUMB32,
    // B.W <label>
    B1_BMI_THUMB32,
    // B.W <label>
    B1_BPL_THUMB32,
    // B.W <label>
    B1_BVS_THUMB32,
    // B.W <label>
    B1_BVC_THUMB32,
    // B.W <label>
    B1_BHI_THUMB32,
    // B.W <label>
    B1_BLS_THUMB32,
    // B.W <label>
    B1_BGE_THUMB32,
    // B.W <label>
    B1_BLT_THUMB32,
    // B.W <label>
    B1_BGT_THUMB32,
    // B.W <label>
    B1_BLE_THUMB32,
	// B.W <label>
	B2_THUMB32,
	// ADR.W Rd, <label>
	ADR1_THUMB32,
	// ADR.W Rd, <label>
	ADR2_THUMB32,
	// LDR.W Rt, <label>
	LDR_THUMB32,
	// TBB [PC, Rm]
	TBB_THUMB32,
	// TBH [PC, Rm, LSL #1]
	TBH_THUMB32,

	// BLX <label>
	BLX_ARM,
	// BL <label>
	BL_ARM,
	// B <label>
	B_ARM,

    // <Add by GToad>
    // B <label>
	BEQ_ARM,
    // B <label>
	BNE_ARM,
    // B <label>
	BCS_ARM,
    // B <label>
	BCC_ARM,
    // B <label>
	BMI_ARM,
    // B <label>
	BPL_ARM,
    // B <label>
	BVS_ARM,
    // B <label>
	BVC_ARM,
    // B <label>
	BHI_ARM,
    // B <label>
	BLS_ARM,
    // B <label>
	BGE_ARM,
    // B <label>
	BLT_ARM,
    // B <label>
	BGT_ARM,
    // B <label>
	BLE_ARM,
    // </Add by GToad>

	// BX PC
	BX_ARM,
	// ADD Rd, PC, Rm (Rd != PC, Rm != PC) 在对ADD进行修正时，采用了替换PC为Rr的方法，当Rd也为PC时，由于之前更改了Rr的值，可能会影响跳转后的正常功能;实际汇编中没有发现Rm也为PC的情况，故未做处理。
	ADD_ARM,
	// ADR Rd, <label>
	ADR1_ARM,
	// ADR Rd, <label>
	ADR2_ARM,
	// MOV Rd, PC
	MOV_ARM,
	// LDR Rt, <label>
	LDR_ARM,

	UNDEFINE,
};

int lengthFixThumb32(uint32_t opcode)
{
    int type;
    type = getTypeInThumb32(opcode);
    switch(type)
    {
        case BLX_THUMB32:
        case BL_THUMB32:
        case B1_THUMB32:return 12;break;
        case B2_THUMB32:return 8;break;
        case ADR1_THUMB32:
        case ADR2_THUMB32:return 8;break;
        case LDR_THUMB32:
        case TBB_THUMB32:
        case TBH_THUMB32:return 28;break;
        case B1_BEQ_THUMB32:
        case B1_BNE_THUMB32:
        case B1_BCS_THUMB32:
        case B1_BCC_THUMB32:
        case B1_BMI_THUMB32:
        case B1_BPL_THUMB32:
        case B1_BVS_THUMB32:
        case B1_BVC_THUMB32:
        case B1_BHI_THUMB32:
        case B1_BLS_THUMB32:
        case B1_BGE_THUMB32:
        case B1_BLT_THUMB32:
        case B1_BGT_THUMB32:
        case B1_BLE_THUMB32:return 12;break;
        case UNDEFINE:return 4;break;
    }    
}

int lengthFixArm32(uint32_t opcode)
{
    int type;
    type = getTypeInArm32(opcode);
    switch(type)
    {
        case BEQ_ARM:
        case BNE_ARM:
        case BCS_ARM:
        case BCC_ARM:
        case BMI_ARM:
        case BPL_ARM:
        case BVS_ARM:
        case BVC_ARM:
        case BHI_ARM:
        case BLS_ARM:
        case BGE_ARM:
        case BLT_ARM:
        case BGT_ARM:
        case BLE_ARM:return 12;break;
        case BLX_ARM:
        case BL_ARM:return 12;break;
        case B_ARM:
        case BX_ARM:return 8;break;
        case ADD_ARM:return 24;break;
        case ADR1_ARM:
        case ADR2_ARM:
        case LDR_ARM:
        case MOV_ARM:return 12;break;
        case UNDEFINE:return 4;
    }    
}

int lengthFixThumb16(uint16_t opcode)
{
    int type;
    type = getTypeInThumb16(opcode);
    switch(type)
    {
        case B1_BEQ_THUMB16:
        case B1_BNE_THUMB16:
        case B1_BCS_THUMB16:
        case B1_BCC_THUMB16:
        case B1_BMI_THUMB16:
        case B1_BPL_THUMB16:
        case B1_BVS_THUMB16:
        case B1_BVC_THUMB16:
        case B1_BHI_THUMB16:
        case B1_BLS_THUMB16:
        case B1_BGE_THUMB16:
        case B1_BLT_THUMB16:
        case B1_BGT_THUMB16:
        case B1_BLE_THUMB16:return 12;break;
        case B1_THUMB16:return 12;break;
        case B2_THUMB16:
        case BX_THUMB16:return 8;break;
        case ADD_THUMB16:return 14;break;
        case MOV_THUMB16:
        case ADR_THUMB16:
        case LDR_THUMB16:return 8;break;
        case CB_THUMB16:return 12;break;
        case UNDEFINE:return 4;break;
    }    
}

static int getTypeInArm32(uint32_t instruction)
{
    LOGI("getTypeInArm : %x", instruction);
	if ((instruction & 0xFE000000) == 0xFA000000) {
		return BLX_ARM;
	}
	if ((instruction & 0xF000000) == 0xB000000) {
		return BL_ARM;
	}
	if ((instruction & 0xFE000000) == 0x0A000000) {
		return BEQ_ARM;
	}
    if ((instruction & 0xFE000000) == 0x1A000000) {
		return BNE_ARM;
	}
    if ((instruction & 0xFE000000) == 0x2A000000) {
		return BCS_ARM;
	}
    if ((instruction & 0xFE000000) == 0x3A000000) {
		return BCC_ARM;
	}
    if ((instruction & 0xFE000000) == 0x4A000000) {
		return BMI_ARM;
	}
    if ((instruction & 0xFE000000) == 0x5A000000) {
		return BPL_ARM;
	}
    if ((instruction & 0xFE000000) == 0x6A000000) {
		return BVS_ARM;
	}
    if ((instruction & 0xFE000000) == 0x7A000000) {
		return BVC_ARM;
	}
    if ((instruction & 0xFE000000) == 0x8A000000) {
		return BHI_ARM;
	}
    if ((instruction & 0xFE000000) == 0x9A000000) {
		return BLS_ARM;
	}
    if ((instruction & 0xFE000000) == 0xAA000000) {
		return BGE_ARM;
	}
    if ((instruction & 0xFE000000) == 0xBA000000) {
		return BLT_ARM;
	}
    if ((instruction & 0xFE000000) == 0xCA000000) {
		return BGT_ARM;
	}
    if ((instruction & 0xFE000000) == 0xDA000000) {
		return BLE_ARM;
	}
    if ((instruction & 0xFE000000) == 0xEA000000) {
		return B_ARM;
	}
    
    /*
    if ((instruction & 0xFF000000) == 0xFA000000) {
		return BLX_ARM;
	} *//*
    if ((instruction & 0xF000000) == 0xA000000) {
		return B_ARM;
	}*/
    
	if ((instruction & 0xFF000FF) == 0x120001F) {
		return BX_ARM;
	}
	if ((instruction & 0xFEF0010) == 0x8F0000) {
		return ADD_ARM;
	}
	if ((instruction & 0xFFF0000) == 0x28F0000) {
		return ADR1_ARM;
	}
	if ((instruction & 0xFFF0000) == 0x24F0000) {
		return ADR2_ARM;		
	}
	if ((instruction & 0xE5F0000) == 0x41F0000) {
		return LDR_ARM;
	}
	if ((instruction & 0xFE00FFF) == 0x1A0000F) {
		return MOV_ARM;
	}
	return UNDEFINE;
}

static int getTypeInThumb16(uint16_t instruction)
{
    LOGI("getTypeInThumb16 : %x", instruction);
    if ((instruction & 0xFF00) == 0xD000) {
		return B1_BEQ_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xD100) {
		return B1_BNE_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xD200) {
		return B1_BCS_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xD300) {
		return B1_BCC_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xD400) {
		return B1_BMI_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xD500) {
		return B1_BPL_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xD600) {
		return B1_BVS_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xD700) {
		return B1_BVC_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xD800) {
		return B1_BHI_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xD900) {
		return B1_BLS_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xDA00) {
		return B1_BGE_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xDB00) {
		return B1_BLT_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xDC00) {
		return B1_BGT_THUMB16;
	}
    if ((instruction & 0xFF00) == 0xDD00) {
		return B1_BLE_THUMB16;
	}
	if ((instruction & 0xF000) == 0xD000) {
		return B1_THUMB16;
	}
	if ((instruction & 0xF800) == 0xE000) {
		return B2_THUMB16;
	}
	if ((instruction & 0xFFF8) == 0x4778) {
		return BX_THUMB16;
	}
	if ((instruction & 0xFF78) == 0x4478) {
		return ADD_THUMB16;
	}
	if ((instruction & 0xFF78) == 0x4678) {
		return MOV_THUMB16;
	}
	if ((instruction & 0xF800) == 0xA000) {
		return ADR_THUMB16;
	}
	if ((instruction & 0xF800) == 0x4800) {
		return LDR_THUMB16;
	}
	if ((instruction & 0xF500) == 0xB100) {
		return CB_THUMB16;
	}
	return UNDEFINE;
}

static int getTypeInThumb32(uint32_t instruction)
{
    LOGI("getTypeInThumb32 : %x", instruction);
	if ((instruction & 0xF800D000) == 0xF000C000) {
		return BLX_THUMB32;
	}
	if ((instruction & 0xF800D000) == 0xF000D000) {
		return BL_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF0008000) {
		return B1_BEQ_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF0408000) {
		return B1_BNE_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF0808000) {
		return B1_BCS_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF0C08000) {
		return B1_BCC_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF1008000) {
		return B1_BMI_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF1408000) {
		return B1_BPL_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF1808000) {
		return B1_BVS_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF1C08000) {
		return B1_BVC_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF2008000) {
		return B1_BHI_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF2408000) {
		return B1_BLS_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF2808000) {
		return B1_BGE_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF2C08000) {
		return B1_BLT_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF3008000) {
		return B1_BGT_THUMB32;
	}
    if ((instruction & 0xFBA0D000) == 0xF3408000) {
		return B1_BLE_THUMB32;
	}
	if ((instruction & 0xF800D000) == 0xF0008000) {
		return B1_THUMB32;
	}
	if ((instruction & 0xF800D000) == 0xF0009000) {
		return B2_THUMB32;
	}
	if ((instruction & 0xFBFF8000) == 0xF2AF0000) {
		return ADR1_THUMB32;
	}
	if ((instruction & 0xFBFF8000) == 0xF20F0000) {
		return ADR2_THUMB32;		
	}
	if ((instruction & 0xFF7F0000) == 0xF85F0000) {
		return LDR_THUMB32;
	}
	if ((instruction & 0xFFFF00F0) == 0xE8DF0000) {
		return TBB_THUMB32;
	}
	if ((instruction & 0xFFFF00F0) == 0xE8DF0010) {
		return TBH_THUMB32;
	}
	return UNDEFINE;
}

bool isThumb32(uint16_t opcode)
{
    LOGI("isThumb32 : opcode is %x",opcode);
    int tmp = opcode >> 11; 
    LOGI("tmp is %d",tmp);
    if ((tmp == 0b11101) || (tmp == 0b11110) || (tmp == 0b11111)){ //TODO: this "if" struct is just for debug.
    // Use "return ((tmp == 0b11101) || (tmp == 0b11110) || (tmp == 0b11111));" when released.
        LOGI("thumb32 !"); 
        return true;
    }
    return false;
}

bool isTargetAddrInBackup(uint32_t target_addr, uint32_t hook_addr, int backup_length)
{
    if((target_addr<=hook_addr+backup_length)&&(target_addr>=hook_addr))
        return true;
    return false;
}

int fixPCOpcodeArm(void *fixOpcodes , INLINE_HOOK_INFO* pstInlineHook)
{
    uint32_t pc;
    uint32_t lr;
    int backUpPos = 0;
    int fixPos = 0;
    int offset = 0;
    //int isConditionBcode = 0;
    uint32_t *currentOpcode;
    uint32_t tmpFixOpcodes[40]; //对于每条PC命令的修复指令都将暂时保存在这里。
    //uint32_t tmpBcodeFix;
    //uint32_t tmpBcodeX = 0;

    LOGI("Fixing Arm !!!!!!!");

    currentOpcode = pstInlineHook->szbyBackupOpcodes + sizeof(uint8_t)*backUpPos;
    LOGI("sizeof(uint8_t) : %D", sizeof(uint8_t));

    pc = pstInlineHook->pHookAddr + 8; //pc变量用于保存原本指令执行时的pc值
    lr = pstInlineHook->pHookAddr + pstInlineHook->backUpLength;

    if(pstInlineHook == NULL)
    {
        LOGI("pstInlineHook is null");
    }

    while(1) // 在这个循环中，每次都处理一个thumb命令
    {
        LOGI("-------------START----------------");
        LOGI("currentOpcode is %x",*currentOpcode);
        
        offset = fixPCOpcodeArm32(pc, lr, *currentOpcode, tmpFixOpcodes, pstInlineHook);
        //LOGI("isConditionBcode : %d", isConditionBcode);
        LOGI("offset : %d", offset);
        memcpy(fixOpcodes+fixPos, tmpFixOpcodes, offset);
        /*
        if (isConditionBcode==1) { // the first code is B??
            if (backUpPos == 4) { // the second has just been processed
                LOGI("Fix the first b_code.");
                LOGI("offset : %d",offset);
                tmpBcodeFix += (offset/4 +1);
                memcpy(fixOpcodes, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 1.");

                tmpBcodeFix = 0xE51FF004;
                LOGI("Fix the first b_code 1.5");
                memcpy(fixOpcodes+fixPos+offset, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 2.");

                tmpBcodeFix = pstInlineHook->pHookAddr + 8;
                memcpy(fixOpcodes+fixPos+offset+4, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 3.");

                tmpBcodeFix = 0xE51FF004;
                memcpy(fixOpcodes+fixPos+offset+8, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 4.");

                tmpBcodeFix = tmpBcodeX;
                memcpy(fixOpcodes+fixPos+offset+12, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 5.");

                offset += 4*4;
            }
            else if (backUpPos == 0) { //save the first B code
                tmpBcodeFix = (*currentOpcode & 0xFE000000);
                tmpBcodeX = (*currentOpcode & 0xFFFFFF) << 2; // x*4
                LOGI("tmpBcodeX : %x", tmpBcodeX);
                tmpBcodeX = tmpBcodeX + 8 + pstInlineHook->pHookAddr;
            }
        }*/
        
        backUpPos += 4; //arm32的话下一次取后面4 byte偏移的指令
        pc += sizeof(uint32_t);

        fixPos += offset;
        LOGI("fixPos : %d", fixPos);
        LOGI("--------------END-----------------");

        if (backUpPos < pstInlineHook->backUpLength)
        {
            currentOpcode = pstInlineHook->szbyBackupOpcodes + sizeof(uint8_t)*backUpPos;
        }
        else{
            LOGI("pstInlineHook->backUpLength : %d", pstInlineHook->backUpLength);
            LOGI("backUpPos : %d",backUpPos);
            LOGI("fixPos : %d", fixPos);
            LOGI("Fix finish !");
            return fixPos;
        }
    }

    LOGI("Something wrong in arm fixing...");

    return 0;
}

int fixPCOpcodeThumb(void *fixOpcodes , INLINE_HOOK_INFO* pstInlineHook)
{
    uint32_t pc;
    uint32_t lr;
    int backUpPos = 0;
    int fixPos = 0;
    int offset = 0;
    uint16_t *currentOpcode;
    BYTE tmpFixOpcodes[40]; //对于每条PC命令的修复指令都将暂时保存在这里。

    LOGI("Fixing Thumb !!!!!!!");

    currentOpcode = pstInlineHook->szbyBackupOpcodes + sizeof(uint8_t)*backUpPos;
    LOGI("sizeof(uint8_t) : %D", sizeof(uint8_t));

    pc = pstInlineHook->pHookAddr - 1 + 4; //pc变量用于保存原本指令执行时的pc值

    if(pstInlineHook == NULL)
    {
        LOGI("pstInlineHook is null");
    }
    
    while(1) // 在这个循环中，每次都处理一个thumb命令
    {
        LOGI("-------------START----------------");
        LOGI("currentOpcode is %x",*currentOpcode);
        if(isThumb32(*currentOpcode)) //先判断它是thumb32还是thumb16
        {
            uint16_t *currentThumb32high = currentOpcode;
            uint16_t *currentThumb32low = currentOpcode+1; //坑：+2就错了，只能+1才是向后2 byte偏移
            LOGI("high_instruction addr : %x",currentThumb32high);
            LOGI("low_instruction addr : %x",currentThumb32low);

            offset = fixPCOpcodeThumb32(pc, *currentThumb32high, *currentThumb32low, tmpFixOpcodes, pstInlineHook);
            LOGI("offset : %d",offset);
            memcpy(fixOpcodes+fixPos, tmpFixOpcodes, offset);
            backUpPos += 4; //thumb32的话下一次取后面4btye偏移的指令
            pc += sizeof(uint32_t);
            LOGI("Current opcode is thumb32 !");
        }
        else{
            offset = fixPCOpcodeThumb16(pc, *currentOpcode, tmpFixOpcodes, pstInlineHook);
            LOGI("offset : %d",offset);
            memcpy(fixOpcodes+fixPos, tmpFixOpcodes, offset);
            backUpPos += 2; //thumb16的话下一次取后面2btye偏移的指令
            pc += sizeof(uint16_t);
        }

        fixPos += offset;
        LOGI("fixPos : %d", fixPos);
        LOGI("--------------END-----------------");

        if (backUpPos < pstInlineHook->backUpLength)
        {
            currentOpcode = pstInlineHook->szbyBackupOpcodes + sizeof(uint8_t)*backUpPos;
            LOGI("backUpPos : %d", backUpPos);
        }
        else{
            LOGI("pstInlineHook->backUpLength : %d", pstInlineHook->backUpLength);
            LOGI("backUpPos : %d",backUpPos);
            LOGI("fixPos : %d", fixPos);
            LOGI("Fix finish !");
            return fixPos;
        }
    }

    lr = pstInlineHook->pHookAddr + backUpPos;

    LOGI("Something wrong in thumb fixing...");

    return 0;
}

int fixPCOpcodeThumb16(uint32_t pc, uint16_t instruction, uint16_t *trampoline_instructions, INLINE_HOOK_INFO* pstInlineHook)
{
	int type;
	int offset;
    uint32_t new_entry_addr = (uint32_t)pstInlineHook->pNewEntryForOldFunction;
	
	type = getTypeInThumb16(instruction);

    if (type == B1_BEQ_THUMB16 || type == B1_BNE_THUMB16 || type == B1_BCS_THUMB16 || type == B1_BCC_THUMB16 || type == B1_BMI_THUMB16
     || type == B1_BPL_THUMB16 || type == B1_BVS_THUMB16 || type == B1_BVC_THUMB16 || type == B1_BHI_THUMB16 || type == B1_BLS_THUMB16
     || type == B1_BGE_THUMB16 || type == B1_BLT_THUMB16 || type == B1_BGT_THUMB16 || type == B1_BLE_THUMB16) {
        LOGI("B1_CONDITION_THUMB16");
        uint32_t x;
		int top_bit;
		uint32_t imm32;
		uint32_t value;

        trampoline_instructions[0] = (uint16_t)(((instruction & 0xFF00)+4)^0x100);
        trampoline_instructions[1] = 0xBF00; //nop

        trampoline_instructions[2] = 0xF8DF;
		trampoline_instructions[3] = 0xF000;	// LDR.W PC, [PC]

        x = (instruction & 0xFF) << 1;
		top_bit = x >> 8;
		imm32 = top_bit ? (x | (0xFFFFFFFF << 8)) : x;
		value = pc + imm32 + 1; // THUMB MODE FOR LDR

        if(isTargetAddrInBackup(value-1,(uint32_t)pstInlineHook->pHookAddr,pstInlineHook->backUpLength)){
            //backup to backup !
            LOGI("BtoB in thumb16");
            int offset_in_backup = 0;
            int cnt = (value - 1 - ((uint32_t)pstInlineHook->pHookAddr - 1))/2;
            for(int i=0;i<cnt;i++){
                offset_in_backup += pstInlineHook->backUpFixLengthList[i];
            }
            value = new_entry_addr + offset_in_backup + 1;
        }
		trampoline_instructions[4] = (value & 0xFFFF);
		trampoline_instructions[5] = value >> 16;

        offset = 6;
	}
	else if (type == B1_THUMB16 || type == B2_THUMB16 || type == BX_THUMB16) {
        LOGI("B1_THUMB16 B2_THUMB16 BX_THUMB16");
		uint32_t x;
		int top_bit;
		uint32_t imm32;
		uint32_t value;
		int idx;
		
		idx = 0;
		if (type == B1_THUMB16) {
            LOGI("B1_THUMB16");
			x = (instruction & 0xFF) << 1;
			top_bit = x >> 8;
			imm32 = top_bit ? (x | (0xFFFFFFFF << 8)) : x;
			value = pc + imm32 + 1;
			trampoline_instructions[idx++] = instruction & 0xFF00;
			trampoline_instructions[idx++] = 0xE003;	// B PC, #6
		}
		else if (type == B2_THUMB16) {
            LOGI("B2_THUMB16");
			x = (instruction & 0x7FF) << 1;
			top_bit = x >> 11;
			imm32 = top_bit ? (x | (0xFFFFFFFF << 11)) : x;
			value = pc + imm32 + 1; //thumb mode for LDR.W
		}
		else if (type == BX_THUMB16) {
            LOGI("BX_THUMB16");
			value = pc + 1;
		}

        if(isTargetAddrInBackup(value-1,(uint32_t)pstInlineHook->pHookAddr,pstInlineHook->backUpLength)){
            //backup to backup !
            LOGI("BtoB in thumb16");
            int offset_in_backup = 0;
            int cnt = (value - 1 - ((uint32_t)pstInlineHook->pHookAddr - 1))/2;
            LOGI("CNT : %d",cnt);
            LOGI("VALUE : %x",value);
            LOGI("HOOK ADDR : %x",(uint32_t)pstInlineHook->pHookAddr)
            for(int i=0;i<cnt;i++){
                offset_in_backup += pstInlineHook->backUpFixLengthList[i];
                LOGI("offset : %d",offset_in_backup);
            }
            value = new_entry_addr + offset_in_backup + 1;
            LOGI("new_entry_addr : %x",new_entry_addr);
            LOGI("NEW VALUE : %x",value);
        }
		
		trampoline_instructions[idx++] = 0xF8DF;
		trampoline_instructions[idx++] = 0xF000;	// LDR.W PC, [PC]
		trampoline_instructions[idx++] = value & 0xFFFF;
		trampoline_instructions[idx++] = value >> 16;
		offset = idx;
	}
	else if (type == ADD_THUMB16) {
        LOGI("ADD_THUMB16");
		int rdn;
		int rm;
		int r;
		
		rdn = ((instruction & 0x80) >> 4) | (instruction & 0x7);
		
		for (r = 7; ; --r) {
			if (r != rdn) {
				break;
			}
		}
		
		trampoline_instructions[0] = 0xB400 | (1 << r);	// PUSH {Rr}
		trampoline_instructions[1] = 0x4802 | (r << 8);	// LDR Rr, [PC, #8]
		trampoline_instructions[2] = (instruction & 0xFF87) | (r << 3); //我猜是adr Rd, Rr, ?
		trampoline_instructions[3] = 0xBC00 | (1 << r);	// POP {Rr}
		trampoline_instructions[4] = 0xE002;	// B PC, #4 ???????
		trampoline_instructions[5] = 0xBF00;
		trampoline_instructions[6] = pc & 0xFFFF;
		trampoline_instructions[7] = pc >> 16;
		offset = 8;
	}
	else if (type == MOV_THUMB16 || type == ADR_THUMB16 || type == LDR_THUMB16) {
        LOGI("MOV_THUMB16 ADR_THUMB16 LDR_THUMB16");
		int r;
		uint32_t value;
		
		if (type == MOV_THUMB16) {
            LOGI("MOV_THUMB16");
			r = instruction & 0x7;
			value = pc;
		}
		else if (type == ADR_THUMB16) {
            LOGI("ADR_THUMB16");
			r = (instruction & 0x700) >> 8;
			value = ALIGN_PC(pc) + (instruction & 0xFF) << 2;
		}
		else {
            LOGI("LDR_THUMB16");
			r = (instruction & 0x700) >> 8; //得到寄存器
			value = ((uint32_t *) (ALIGN_PC(pc) + ((instruction & 0xFF) << 2)))[0];
		}

		trampoline_instructions[0] = 0x4800 | (r << 8);	// LDR Rd, [PC]
		trampoline_instructions[1] = 0xE001;	// B PC, #2
		trampoline_instructions[2] = value & 0xFFFF;
		trampoline_instructions[3] = value >> 16;
		//offset = 4;
        offset = 4;
	}
	else if (type == CB_THUMB16) {
        LOGI("CB_THUMB16");
		int nonzero;
		uint32_t imm32;
		uint32_t value;

		nonzero = (instruction & 0x800) >> 11;
		imm32 = ((instruction & 0x200) >> 3) | ((instruction & 0xF8) >> 2);
		value = pc + imm32 + 1;

		trampoline_instructions[0] = instruction & 0xFD07;
		trampoline_instructions[1] = 0xE003;	// B PC, #6
		trampoline_instructions[2] = 0xF8DF;
		trampoline_instructions[3] = 0xF000;	// LDR.W PC, [PC]
		trampoline_instructions[4] = value & 0xFFFF;
		trampoline_instructions[5] = value >> 16;
		offset = 6;
	}
	else {
        LOGI("OTHER_THUMB16");
		trampoline_instructions[0] = instruction;
		trampoline_instructions[1] = 0xBF00;  // NOP
		offset = 2;
	}
	
	return offset*2;
}

int fixPCOpcodeArm32(uint32_t pc, uint32_t lr, uint32_t instruction, uint32_t *trampoline_instructions, INLINE_HOOK_INFO* pstInlineHook)
{
    int type;
	//int offset;
    int trampoline_pos;
    uint32_t new_entry_addr = (uint32_t)pstInlineHook->pNewEntryForOldFunction;
    LOGI("new_entry_addr : %x",new_entry_addr);

    trampoline_pos = 0;
    LOGI("THE ARM32 OPCODE IS %x",instruction);
    type = getTypeInArm32(instruction);
    //type = getTypeInArm(instruction); //判断该arm指令的种类
    if (type == BEQ_ARM || type == BNE_ARM || type == BCS_ARM || type == BCC_ARM || 
        type == BMI_ARM || type == BPL_ARM || type == BVS_ARM || type == BVC_ARM || 
        type == BHI_ARM || type == BLS_ARM || type == BGE_ARM || type == BLT_ARM || 
        type == BGT_ARM || type == BLE_ARM) {
        LOGI("BEQ_ARM BNE_ARM BCS_ARM BCC_ARM BMI_ARM BPL_ARM BVS_ARM BVC_ARM BHI_ARM BLS_ARM BGE_ARM BLT_ARM BGT_ARM BLE_ARM");
		uint32_t x;
		int top_bit;
		uint32_t imm32;
		uint32_t value;
//        uint32_t flag=0;
        //uint32_t ins_info;

        trampoline_instructions[trampoline_pos++] = (uint32_t)(((instruction & 0xFE000000)+1)^0x10000000);
        trampoline_instructions[trampoline_pos++] = 0xE51FF004; // LDR PC, [PC, #-4]
/*        flag = (uint32_t)(instruction & 0xFFFFFF);
        if (flag == 0xffffff) {
            LOGI("BACKUP TO BACKUP !");

        }*/

        x = (instruction & 0xFFFFFF) << 2; // 4*x
        top_bit = x >> 25;
		imm32 = top_bit ? (x | (0xFFFFFFFF << 26)) : x;
        value = x + pc;
        if(isTargetAddrInBackup(value, (uint32_t)pstInlineHook->pHookAddr, pstInlineHook->backUpLength)){
            LOGI("B TO B in Arm32");
            int offset_in_backup;
            int cnt = (value - (uint32_t)pstInlineHook->pHookAddr)/4;
            if(cnt==0){
                value = new_entry_addr;
            }else if(cnt==1){
                value = new_entry_addr + pstInlineHook->backUpFixLengthList[0];
            }else{
                LOGI("cnt !=1or0, something wrong !");
            }
            //value = new_entry_addr+12;
        }
        trampoline_instructions[trampoline_pos++] = value; // hook_addr + 12 + 4*x

        /*
        if (backUpPos == 0) { //the B_code is the first backup code
            *isConditionBcode = 1;
            //ins_info = (uint32_t)(instruction & 0xF0000000)>>28;
            LOGI("INS_INFO : %x", ins_info);

            trampoline_instructions[trampoline_pos++] = (uint32_t)(((instruction & 0xFE000000)+1)^0x10000000); //B??_ARM 16 -> 0X?A000002
            LOGI("B code on the first.");
            LOGI("%x",(uint32_t)(instruction & 0xFE000000));
        }
        else if (backUpPos == 4) { //THE B_code is the second backup code
            LOGI("B code on the second.");
            trampoline_instructions[trampoline_pos++] = (uint32_t)(instruction & 0xFE000000)+1; //B??_ARM 12 -> 0X?A000001
            LOGI("%x",(uint32_t)(instruction & 0xFE000000)+1);

            trampoline_instructions[trampoline_pos++] = 0xE51FF004; // LDR PC, [PC, #-4]
            value = pc-4;
            trampoline_instructions[trampoline_pos++] = value; // hook_addr + 8

            trampoline_instructions[trampoline_pos++] = 0xE51FF004; // LDR PC, [PC, #-4]
            x = (instruction & 0xFFFFFF) << 2; // 4*x
            value = x + pc;
            trampoline_instructions[trampoline_pos++] = value; // hook_addr + 12 + 4*x
        }*/

        return 4*trampoline_pos;
    }
	if (type == BLX_ARM || type == BL_ARM || type == B_ARM || type == BX_ARM) {
        LOGI("BLX_ARM BL_ARM B_ARM BX_ARM");
		uint32_t x;
		int top_bit;
		uint32_t imm32;
		uint32_t value;
//        uint32_t flag = 0;

		if (type == BLX_ARM || type == BL_ARM) {
            LOGI("BLX_ARM BL_ARM");
			trampoline_instructions[trampoline_pos++] = 0xE28FE004;	// ADD LR, PC, #4
		}
		trampoline_instructions[trampoline_pos++] = 0xE51FF004;  	// LDR PC, [PC, #-4]
		if (type == BLX_ARM) {
            LOGI("BLX_ARM");
			x = ((instruction & 0xFFFFFF) << 2) | ((instruction & 0x1000000) >> 23); //BLX_ARM
            LOGI("BLX_ARM : X : %d",x);
		}
		else if (type == BL_ARM || type == B_ARM) {
            LOGI("BL_ARM B_ARM");
			x = (instruction & 0xFFFFFF) << 2;                                       //BL_ARM B_ARM
/*            flag = (uint32_t)(instruction & 0xFFFFFF);
            if (flag == 0xffffff) {
                LOGI("BACKUP TO BACKUP !");
            }*/
		}
		else {
            LOGI("BX_ARM");
			x = 0;                                                                   //BX_ARM
		}
		
		top_bit = x >> 25;
		imm32 = top_bit ? (x | (0xFFFFFFFF << 26)) : x;
        LOGI("top_bit : %d",top_bit);
        LOGI("imm32 : %d",imm32);
        LOGI("PC : %d",pc);

		if (type == BLX_ARM) {
            LOGI("BLX_ARM");
			value = pc + imm32 + 1;
            LOGI("BLX_ARM : value : %d",imm32);
		}
		else {
            LOGI("BL_ARM B_ARM BX_ARM");
			value = pc + imm32;
            LOGI("value : %d", value);
            if(isTargetAddrInBackup(value, (uint32_t)pstInlineHook->pHookAddr, pstInlineHook->backUpLength)){
                LOGI("Backup to backup!");
                value = new_entry_addr+4*(trampoline_pos+1);
            }
		}
		trampoline_instructions[trampoline_pos++] = value;
		
	}
	else if (type == ADD_ARM) {
        LOGI("ADD_ARM");
		int rd;
		int rm;
		int r;
		
		rd = (instruction & 0xF000) >> 12;
		rm = instruction & 0xF;
		
		for (r = 12; ; --r) { //找一个既不是rm,也不是rd的寄存器
			if (r != rd && r != rm) {
				break;
			}
		}
		
		trampoline_instructions[trampoline_pos++] = 0xE52D0004 | (r << 12);	// PUSH {Rr}
		trampoline_instructions[trampoline_pos++] = 0xE59F0008 | (r << 12);	// LDR Rr, [PC, #8]
		trampoline_instructions[trampoline_pos++] = (instruction & 0xFFF0FFFF) | (r << 16);
		trampoline_instructions[trampoline_pos++] = 0xE49D0004 | (r << 12);	// POP {Rr}
		trampoline_instructions[trampoline_pos++] = 0xE28FF000;	// ADD PC, PC MFK!这明明是ADD PC, PC, #0好么！
		trampoline_instructions[trampoline_pos++] = pc;
	}
	else if (type == ADR1_ARM || type == ADR2_ARM || type == LDR_ARM || type == MOV_ARM) {
        LOGI("ADR1_ARM ADR2_ARM LDR_ARM MOV_ARM");
		int r;
		uint32_t value;
		
		r = (instruction & 0xF000) >> 12;
		
		if (type == ADR1_ARM || type == ADR2_ARM || type == LDR_ARM) {
            LOGI("ADR1_ARM ADR2_ARM LDR_ARM");
			uint32_t imm32;
			
			imm32 = instruction & 0xFFF;
			if (type == ADR1_ARM) {
                LOGI("ADR1_ARM");
				value = pc + imm32;
			}
			else if (type == ADR2_ARM) {
                LOGI("ADR2_ARM");
				value = pc - imm32;
			}
			else if (type == LDR_ARM) {
                LOGI("LDR_ARM");
				int is_add;
	
				is_add = (instruction & 0x800000) >> 23;
				if (is_add) {
					value = ((uint32_t *) (pc + imm32))[0];
				}
				else {
					value = ((uint32_t *) (pc - imm32))[0];
				}
			}
		}
		else {
            LOGI("MOV_ARM");
			value = pc;
		}
			
		trampoline_instructions[trampoline_pos++] = 0xE51F0000 | (r << 12);	// LDR Rr, [PC]
		trampoline_instructions[trampoline_pos++] = 0xE28FF000;	// ADD PC, PC
		trampoline_instructions[trampoline_pos++] = value;
	}
	else {
        LOGI("OTHER_ARM");
		trampoline_instructions[trampoline_pos++] = instruction;
        return 4*trampoline_pos;
	}
	//pc += sizeof(uint32_t);
	
	//trampoline_instructions[trampoline_pos++] = 0xe51ff004;	// LDR PC, [PC, #-4]
	//trampoline_instructions[trampoline_pos++] = lr;
    return 4*trampoline_pos;
}

int fixPCOpcodeThumb32(uint32_t pc, uint16_t high_instruction, uint16_t low_instruction, uint16_t *trampoline_instructions, INLINE_HOOK_INFO* pstInlineHook)
{
	uint32_t instruction;
	int type;
	int idx;
	int offset;
    uint32_t new_entry_addr = (uint32_t)pstInlineHook->pNewEntryForOldFunction;
	LOGI("THE THUMB32 LOW OPCODE IS %x",low_instruction);
	instruction = (high_instruction << 16) | low_instruction;
    LOGI("THE THUMB32 OPCODE IS %x",instruction);
	type = getTypeInThumb32(instruction);
	idx = 0;
    if (type == B1_BEQ_THUMB32 || type == B1_BNE_THUMB32 || type == B1_BCS_THUMB32 || type == B1_BCC_THUMB32 || type == B1_BMI_THUMB32
     || type == B1_BPL_THUMB32 || type == B1_BVS_THUMB32 || type == B1_BVC_THUMB32 || type == B1_BHI_THUMB32 || type == B1_BLS_THUMB32
     || type == B1_BGE_THUMB32 || type == B1_BLT_THUMB32 || type == B1_BGT_THUMB32 || type == B1_BLE_THUMB32) {
        LOGI("B1_CONDITION_THUMB32");
        LOGI("THUMB32 OPCODE : %x",instruction);
        uint32_t x;
		int top_bit;
		uint32_t imm32;
		uint32_t value;
        uint32_t j1;
		uint32_t j2;
		uint32_t s;


        //0b 0000 0000 0011 1111 0010 1111 1111 1111 通过填入大数值1048574得到储存数值的位
        //&0b1111 1111 1100 0000 1101 0000 0000 0000

        trampoline_instructions[0] = (uint16_t)((high_instruction &0xFFC0)^0x40);
        trampoline_instructions[1] = (uint16_t)((low_instruction &0xD000)+12/2); //取反后 BXX.W 12

        trampoline_instructions[2] = 0xF8DF;
		trampoline_instructions[3] = 0xF000;	// LDR.W PC, [PC]

        j1 = (low_instruction & 0x2000) >> 13;
		j2 = (low_instruction & 0x800) >> 11;
        s = (high_instruction & 0x400) >> 10;
        x = (s << 20) | (j2 << 19) | (j1 << 18) | ((high_instruction & 0x3F) << 12) | ((low_instruction & 0x7FF) << 1);
		imm32 = s ? (x | (0xFFFFFFFF << 21)) : x;
		value = pc + imm32 + 1;

        if(isTargetAddrInBackup(value-1,(uint32_t)pstInlineHook->pHookAddr,pstInlineHook->backUpLength)){
            //backup to backup !
            LOGI("BtoB in thumb32");
            int offset_in_backup = 0;
            int cnt = (value - 1 - ((uint32_t)pstInlineHook->pHookAddr - 1))/2;
            for(int i=0;i<cnt;i++){
                offset_in_backup += pstInlineHook->backUpFixLengthList[i];
            }
            value = new_entry_addr + offset_in_backup + 1;
        }

        trampoline_instructions[4] = (value & 0xFFFF);
		trampoline_instructions[5] = value >> 16;

        offset = 6;
     }else if (type == BLX_THUMB32 || type == BL_THUMB32 || type == B1_THUMB32 || type == B2_THUMB32) {
		uint32_t j1;
		uint32_t j2;
		uint32_t s;
		uint32_t i1;
		uint32_t i2;
		uint32_t x;
		uint32_t imm32;
		uint32_t value;

		j1 = (low_instruction & 0x2000) >> 13;
		j2 = (low_instruction & 0x800) >> 11;
		s = (high_instruction & 0x400) >> 10;
		i1 = !(j1 ^ s);
		i2 = !(j2 ^ s);

		if (type == BLX_THUMB32 || type == BL_THUMB32) {
            LOGI("BLX_THUMB32 BL_THUMB32");
			trampoline_instructions[idx++] = 0xF20F;
			trampoline_instructions[idx++] = 0x0E09;	// ADD.W LR, PC, #9
		}
		else if (type == B1_THUMB32) {
            LOGI("B1_THUMB32");
			trampoline_instructions[idx++] = 0xD000 | ((high_instruction & 0x3C0) << 2);
			trampoline_instructions[idx++] = 0xE003;	// B PC, #6
		}
		trampoline_instructions[idx++] = 0xF8DF;
		trampoline_instructions[idx++] = 0xF000;	// LDR.W PC, [PC]
		if (type == BLX_THUMB32) {
            LOGI("BLX_THUMB32");
			x = (s << 24) | (i1 << 23) | (i2 << 22) | ((high_instruction & 0x3FF) << 12) | ((low_instruction & 0x7FE) << 1);
			imm32 = s ? (x | (0xFFFFFFFF << 25)) : x;
			value = pc + imm32;
            LOGI("blx_thumb32 : value : %x",value);
		}
		else if (type == BL_THUMB32) {
            LOGI("BL_THUMB32");
			x = (s << 24) | (i1 << 23) | (i2 << 22) | ((high_instruction & 0x3FF) << 12) | ((low_instruction & 0x7FF) << 1);
			imm32 = s ? (x | (0xFFFFFFFF << 25)) : x;
			value = pc + imm32 + 1;
		}
		else if (type == B1_THUMB32) {
            LOGI("B1_THUMB32");
			x = (s << 20) | (j2 << 19) | (j1 << 18) | ((high_instruction & 0x3F) << 12) | ((low_instruction & 0x7FF) << 1);
			imm32 = s ? (x | (0xFFFFFFFF << 21)) : x;
			value = pc + imm32 + 1;
		}
		else if (type == B2_THUMB32) {
            LOGI("B2_THUMB32");
			x = (s << 24) | (i1 << 23) | (i2 << 22) | ((high_instruction & 0x3FF) << 12) | ((low_instruction & 0x7FF) << 1);
			imm32 = s ? (x | (0xFFFFFFFF << 25)) : x;
			value = pc + imm32 + 1;
		}
		trampoline_instructions[idx++] = value & 0xFFFF;
		trampoline_instructions[idx++] = value >> 16;
		offset = idx;
	}
	else if (type == ADR1_THUMB32 || type == ADR2_THUMB32 || type == LDR_THUMB32) {
        LOGI("ADR1_THUMB32 ADR2_THUMB32 LDR_THUMB32");
		int r;
		uint32_t imm32;
		uint32_t value;
		
		if (type == ADR1_THUMB32 || type == ADR2_THUMB32) {
            LOGI("ADR1_THUMB32 ADR2_THUMB32");
			uint32_t i;
			uint32_t imm3;
			uint32_t imm8;
		
			r = (low_instruction & 0xF00) >> 8;
			i = (high_instruction & 0x400) >> 10;
			imm3 = (low_instruction & 0x7000) >> 12;
			imm8 = instruction & 0xFF;
			
			imm32 = (i << 31) | (imm3 << 30) | (imm8 << 27);
			
			if (type == ADR1_THUMB32) {
                LOGI("ADR1_THUMB32");
				value = ALIGN_PC(pc) + imm32;
			}
			else {
                LOGI("ADR2_THUMB32");
				value = ALIGN_PC(pc) - imm32;
			}
		}
		else {
            LOGI("LDR_THUMB32");
			int is_add;
			uint32_t *addr;
			
			is_add = (high_instruction & 0x80) >> 7;
			r = low_instruction >> 12;
			imm32 = low_instruction & 0xFFF;
			
			if (is_add) {
				addr = (uint32_t *) (ALIGN_PC(pc) + imm32);
			}
			else {
				addr = (uint32_t *) (ALIGN_PC(pc) - imm32);
			}
			
			value = addr[0];
		}
		
		trampoline_instructions[0] = 0x4800 | (r << 8);	// LDR Rr, [PC]
		trampoline_instructions[1] = 0xE001;	// B PC, #2
		trampoline_instructions[2] = value & 0xFFFF;
		trampoline_instructions[3] = value >> 16;
		offset = 4;
	}

	else if (type == TBB_THUMB32 || type == TBH_THUMB32) {
        LOGI("TBB_THUMB32 TBH_THUMB32");
		int rm;
		int r;
		int rx;
		
		rm = low_instruction & 0xF;
		
		for (r = 7;; --r) {
			if (r != rm) {
				break;
			}
		}
		
		for (rx = 7; ; --rx) {
			if (rx != rm && rx != r) {
				break;
			}
		}
		
		trampoline_instructions[0] = 0xB400 | (1 << rx);	// PUSH {Rx}
		trampoline_instructions[1] = 0x4805 | (r << 8);	// LDR Rr, [PC, #20]
		trampoline_instructions[2] = 0x4600 | (rm << 3) | rx;	// MOV Rx, Rm
		if (type == TBB_THUMB32) {
            LOGI("TBB_THUMB32");
			trampoline_instructions[3] = 0xEB00 | r;
			trampoline_instructions[4] = 0x0000 | (rx << 8) | rx;	// ADD.W Rx, Rr, Rx
			trampoline_instructions[5] = 0x7800 | (rx << 3) | rx; 	// LDRB Rx, [Rx]
		}
		else if (type == TBH_THUMB32) {
            LOGI("TBH_THUMB32");
			trampoline_instructions[3] = 0xEB00 | r;
			trampoline_instructions[4] = 0x0040 | (rx << 8) | rx;	// ADD.W Rx, Rr, Rx, LSL #1
			trampoline_instructions[5] = 0x8800 | (rx << 3) | rx; 	// LDRH Rx, [Rx]
		}
		trampoline_instructions[6] = 0xEB00 | r;
		trampoline_instructions[7] = 0x0040 | (r << 8) | rx;	// ADD Rr, Rr, Rx, LSL #1
		trampoline_instructions[8] = 0x3001 | (r << 8);	// ADD Rr, #1
		trampoline_instructions[9] = 0xBC00 | (1 << rx);	// POP {Rx}
		trampoline_instructions[10] = 0x4700 | (r << 3);	// BX Rr
		trampoline_instructions[11] = 0xBF00;
		trampoline_instructions[12] = pc & 0xFFFF;
		trampoline_instructions[13] = pc >> 16;
		offset = 14;
	}
	else {
        LOGI("OTHER_THUMB32");
		trampoline_instructions[0] = high_instruction;
		trampoline_instructions[1] = low_instruction;
		offset = 2;
	}

	return offset*2;
}