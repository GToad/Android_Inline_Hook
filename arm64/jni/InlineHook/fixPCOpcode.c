#include "fixPCOpcode.h"

//这里的代码建议看文章：《Android Inline Hook中的指令修复详解》（https://gtoad.github.io/2018/07/13/Android-Inline-Hook-Fix/）

enum INSTRUCTION_TYPE {


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


	ADR_ARM64,

	ADRP_ARM64,

	LDR_ARM64,

	B_ARM64,

	B_COND_ARM64,

	BR_ARM64,

	BL_ARM64,

	BLR_ARM64,

	CBNZ_ARM64,

	CBZ_ARM64,

	TBNZ_ARM64,

	TBZ_ARM64,

	LDR_ARM64_32,

	UNDEFINE,
};


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



static int getTypeInArm64(uint32_t instruction)
{
    LOGI("getTypeInArm64 : %x", instruction);
	if ((instruction & 0x9F000000) == 0x10000000) {
		return ADR_ARM64;
	}
	if ((instruction & 0x9F000000) == 0x90000000) {
		return ADRP_ARM64;
	}
    if ((instruction & 0xFC000000) == 0x14000000) {
		return B_ARM64;
	}
    if ((instruction & 0xFF000010) == 0x54000010) {
		return B_COND_ARM64;
	}
    if ((instruction & 0xFC000000) == 0x94000000) {
		return BL_ARM64;
	}


    if ((instruction & 0xFF000000) == 0x58000000) {//LDR Lliteral need to learn
		return LDR_ARM64;
	}
	if ((instruction & 0x7F000000) == 0x35000000) {
		return CBNZ_ARM64;
	}
	if ((instruction & 0x7F000000) == 0x34000000) {
		return CBZ_ARM64;
	}
	if ((instruction & 0x7F000000) == 0x37000000) {
		return TBNZ_ARM64;
	}
	if ((instruction & 0x7F000000) == 0x36000000) {
		return TBZ_ARM64;
	}

	if ((instruction & 0xFF000000) == 0x18000000) {//LDR Lliteral 32 need to learn
		return LDR_ARM64_32;
	}
	
	return UNDEFINE;
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



bool isTargetAddrInBackup(uint32_t target_addr, uint32_t hook_addr, int backup_length)
{
    if((target_addr<=hook_addr+backup_length)&&(target_addr>=hook_addr))
        return true;
    return false;
}

int fixPCOpcodeArm(void *fixOpcodes , INLINE_HOOK_INFO* pstInlineHook)
{
    uint64_t pc;
    uint64_t lr;
    int backUpPos = 0;
    int fixPos = 0;
    int offset = 0;
    //int isConditionBcode = 0;
    uint32_t *currentOpcode;
    uint32_t tmpFixOpcodes[40]; //对于每条PC命令的修复指令都将暂时保存在这里。
    //uint32_t tmpBcodeFix;
    //uint32_t tmpBcodeX = 0;
	//trampoline_instructions[trampoline_pos++] == 0xf85f83e0; // ldr x0, [sp, #-0x8] recover the x0 register

    LOGI("Fixing Arm !!!!!!!");

    currentOpcode = pstInlineHook->szbyBackupOpcodes + sizeof(uint8_t)*backUpPos;
    LOGI("sizeof(uint8_t) : %D", sizeof(uint8_t));

    pc = pstInlineHook->pHookAddr; //pc变量用于保存原本指令执行时的pc值
    lr = pstInlineHook->pHookAddr + pstInlineHook->backUpLength;

    if(pstInlineHook == NULL)
    {
        LOGI("pstInlineHook is null");
    }

	tmpFixOpcodes[0] = 0xf85f83e0; // ldr x0, [sp, #-0x8] recover the x0 register
	offset = 4;
	memcpy(fixOpcodes+fixPos, tmpFixOpcodes, offset);
	fixPos=+offset;

    while(1) // 在这个循环中，每次都处理一个arm64命令
    {
        //LOGI("-------------START----------------");
        LOGI("currentOpcode is %x",*currentOpcode);
        
        offset = fixPCOpcodeArm64(pc, lr, *currentOpcode, tmpFixOpcodes, pstInlineHook);
        //LOGI("isConditionBcode : %d", isConditionBcode);
        //LOGI("offset : %d", offset);
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
        //LOGI("fixPos : %d", fixPos);
        //LOGI("--------------END-----------------");

        if (backUpPos < pstInlineHook->backUpLength)
        {
			LOGI("ONE FINISH");
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

int fixPCOpcodeArm64(uint64_t pc, uint64_t lr, uint32_t instruction, uint32_t *trampoline_instructions, INLINE_HOOK_INFO* pstInlineHook)
{
    int type;
	//int offset;
    int trampoline_pos;
    uint32_t new_entry_addr = (uint32_t)pstInlineHook->pNewEntryForOldFunction;
    LOGI("new_entry_addr : %x",new_entry_addr);

    trampoline_pos = 0;
	//trampoline_instructions[trampoline_pos++] == 0xf85f83e0; // ldr x0, [sp, #-0x8] recover the x0 register
    LOGI("THE ARM64 OPCODE IS %x",instruction);
    type = getTypeInArm64(instruction);
    //type = getTypeInArm(instruction); //判断该arm指令的种类
	if (type == ADR_ARM64) {
		//LDR Rn, 4
		//PC+imm*4
        LOGI("ADR_ARM64");
		uint32_t imm21;
		uint64_t value;
		uint32_t rd;
		imm21 = ((instruction & 0xFFFFE0)>>3) + ((instruction & 0x60000000)>>29);
		value = pc + 4*imm21;
		if((imm21 & 0x100000)==0x100000)
		{
			LOGI("NEG");
			value = pc - 4 * (0x1fffff - imm21 + 1);
		}
		LOGI("value : %x",value);
		
		rd = instruction & 0x1f;
		trampoline_instructions[trampoline_pos++] = 0x58000020+rd; // ldr rd, 4
		trampoline_instructions[trampoline_pos++] = (uint32_t)(value >> 32);
		trampoline_instructions[trampoline_pos++] = (uint32_t)(value & 0xffffffff);

        return 4*trampoline_pos;
    }
    if (type == ADRP_ARM64) {
		//LDR Rn, 4
		//PC+imm*4096
        LOGI("ADRP_ARM64");
		uint32_t imm21;
		uint64_t value;
		uint32_t rd;
		imm21 = ((instruction & 0xFFFFE0)>>3) + ((instruction & 0x60000000)>>29);
		value = pc + 4096*imm21;
		if((imm21 & 0x100000)==0x100000)
		{
			LOGI("NEG");
			value = pc - 4096 * (0x1fffff - imm21 + 1);
		}
		LOGI("value : %x",value);
		
		rd = instruction & 0x1f;
		trampoline_instructions[trampoline_pos++] = 0x58000020+rd; // ldr rd, 4
		trampoline_instructions[trampoline_pos++] = (uint32_t)(value >> 32);
		trampoline_instructions[trampoline_pos++] = (uint32_t)(value & 0xffffffff);

        return 4*trampoline_pos;
    }
    if (type == LDR_ARM64) {
		//STP Xt, Xn, [SP, #-0x10]
		//LDR Xn, 16
		//LDR Xt, [Xn, 0]
		//LDR Xn, [sp, #-0x8]
		//B 8
		//PC+imm*4
        LOGI("LDR_ARM64");
		uint32_t imm19;
		uint64_t value;
		uint32_t rt;
		uint32_t rn;
		rt = instruction & 0x1f;
		int i;
		for(i=0;i<31;i++)
		{
			if(i!=rt){
				rn = i;
				break;
			}
		}
		LOGI("Rn : %d",rn);
		imm19 = ((instruction & 0xFFFFE0)>>5);
		trampoline_instructions[trampoline_pos++] = 0xa93f03e0 + rt + (rn << 10); //STP Xt, Xn, [SP, #-0x10]
		trampoline_instructions[trampoline_pos++] = 0x58000080 + rn; //LDR Xn, 16
		trampoline_instructions[trampoline_pos++] = 0xf9400000 + (rn << 5); //LDR Xt, [Xn, 0]
		trampoline_instructions[trampoline_pos++] = 0xf85f83e0 + rn; //LDR Xn, [sp, #-0x8]
		trampoline_instructions[trampoline_pos++] = 0x14000002; //B 8

		value = pc + 4*imm19;
		if((imm19 & 0x40000)==0x40000){
			value = pc - 4*(0x7ffff-imm19+1);
		}
		trampoline_instructions[trampoline_pos++] = (uint32_t)(value >> 32);
		trampoline_instructions[trampoline_pos++] = (uint32_t)(value & 0xffffffff);

        return 4*trampoline_pos;
    }
	if (type == B_ARM64) {
		//STP X_tmp1, X_tmp2, [SP, -0x10]
		//LDR X_tmp2, ?
		//[target instruction fix code] if you want
		//BR X_tmp2
		//B 8
		//PC+imm*4
        LOGI("B_ARM64");
		uint32_t target_ins;
		uint32_t imm26;
		uint64_t value;

		imm26 = instruction & 0x3FFFFFF;
		value = pc + imm26*4;
		if((imm26>>25)==1){
			value = pc - 4*(0x3ffffff-imm26+1);
		}
		target_ins = *((uint32_t *)value);
		LOGI("target_ins : %x",target_ins);

		trampoline_instructions[trampoline_pos++] = 0xa93f03e0; //STP X0, X0, [SP, -0x10] default
		trampoline_instructions[trampoline_pos++] = 0x58000080; //LDR X0, 16
		trampoline_instructions[trampoline_pos++] = target_ins; //[target instruction fix code] if you want
		trampoline_instructions[trampoline_pos++] = 0xd61f0000; //BR X0
		trampoline_instructions[trampoline_pos++] = 0x14000002; //B 8
		trampoline_instructions[trampoline_pos++] = (uint32_t)(value >> 32);
		trampoline_instructions[trampoline_pos++] = (uint32_t)(value & 0xffffffff);

        return 4*trampoline_pos;
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

