#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#define ADDRESS 0x1000000
#define MAX_SIMILAR_INSTRUCTIONS 5
#define MAX_INSTRUCTION_STRING 256
#define STACK_ADDRESS 0x2000000
#define STACK_SIZE 0x100000


struct instruction_map {
    const char *key;
    const char *similar[MAX_SIMILAR_INSTRUCTIONS];
    int count;
};

static const struct instruction_map similar_instructions[] = {
    {"ADD", {"SUB", "ADC", "SBC", "RSB"}, 5},
    {"SUB", {"ADD", "SBC", "ADC", "RSB"}, 5},
    {"AND", {"ORR", "EOR", "BIC", "ORN"}, 5},
    {"ORR", {"AND", "EOR", "BIC", "ORN"}, 5},
    {"MOV", {"MVN", "MOVW", "MOVT", "MOVEQ"}, 5},
    {"LSL", {"LSR", "ASR", "ROR", "RRX"}, 5},
    {"LDR", {"STR", "LDRB", "STRB", "LDRH"}, 5},
    {"STR", {"LDR", "STRB", "LDRB", "STRH"}, 5},
    {"PUSH", {"POP", "STMDB", "LDMIA", "STMFD"}, 5},
    {"MUL", {"MLA", "UMULL", "SMULL", "MLS"}, 5},
    {"CMP", {"CMN", "TST", "TEQ", "CMPNE"}, 5},
    {"B", {"BL", "BX", "BLX", "BEQ"}, 5}
};

// Global variables
uc_engine *uc;
int initialized = 0;
FILE *outfile = NULL;
uint64_t coverage_map[65536] = {0}; // Track executed blocks
size_t unique_paths = 0;

// Function prototypes
void ReplaceWithSimilarInstruction(cs_insn *insn);
void AdjustMemoryDisplacement(cs_insn *instruction, unsigned int Seed);
void ModifyMemoryBaseOrIndex(cs_insn *instruction, unsigned int Seed);
void MutateConditionCode(cs_insn *insn);
void ApplyBitwiseOperationsToImmediate(cs_insn *instruction, unsigned int Seed);
void MutateStackOperation(cs_insn *insn, unsigned int Seed);
void MutateBranchTarget(cs_insn *insn, unsigned int Seed);
void MutateRegisters(cs_insn *insn, unsigned int Seed);

// Callback for code coverage tracking
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint32_t block_index = (address - ADDRESS) / 16;
    if (block_index < 65536 && !coverage_map[block_index]) {
        coverage_map[block_index] = 1;
        unique_paths++;
    }
}

void ReplaceWithSimilarInstruction(cs_insn *insn) {
    if (insn == NULL || insn->mnemonic == NULL) {
        return;
    }
    
    for (size_t i = 0; i < sizeof(similar_instructions) / sizeof(similar_instructions[0]); i++) {
        if (strcmp(insn->mnemonic, similar_instructions[i].key) == 0) {
            int idx = rand() % similar_instructions[i].count;
            snprintf(insn->mnemonic, CS_MNEMONIC_SIZE, "%s", similar_instructions[i].similar[idx]);
            break;
        }
    }
}

void AdjustMemoryDisplacement(cs_insn *instruction, unsigned int Seed) {
    if (instruction == NULL || instruction->detail == NULL || 
        instruction->detail->arm.op_count == 0) {
        return;
    }
    
    for (int i = 0; i < instruction->detail->arm.op_count; i++) {
        cs_arm_op *op = &instruction->detail->arm.operands[i];
        if (op->type == ARM_OP_MEM) {
            int32_t disp = op->mem.disp;
            if (rand_r(&Seed) % 2) {
                disp += (rand_r(&Seed) % 100) + 1;
            } else {
                disp -= (rand_r(&Seed) % 100) + 1;
            }
            op->mem.disp = disp;
        }
    }
}

void ModifyMemoryBaseOrIndex(cs_insn *instruction, unsigned int Seed) {
    if (instruction == NULL || instruction->detail == NULL || 
        instruction->detail->arm.op_count == 0) {
        return;
    }
    
    for (int i = 0; i < instruction->detail->arm.op_count; i++) {
        cs_arm_op *op = &instruction->detail->arm.operands[i];
        if (op->type == ARM_OP_MEM) {
            if (op->mem.base != ARM_REG_INVALID) {
                op->mem.base = (arm_reg)(ARM_REG_R0 + (rand_r(&Seed) % 13));
            }
            if (op->mem.index != ARM_REG_INVALID) {
                op->mem.index = (arm_reg)(ARM_REG_R0 + (rand_r(&Seed) % 13));
            }
        }
    }
}

void MutateConditionCode(cs_insn *insn) {
    if (insn == NULL || insn->detail == NULL) {
        return;
    }
    
    static const arm_cc condition_codes[] = {
        ARM_CC_EQ, ARM_CC_NE, ARM_CC_HS, ARM_CC_LO, ARM_CC_MI,
        ARM_CC_PL, ARM_CC_VS, ARM_CC_VC, ARM_CC_HI, ARM_CC_LS,
        ARM_CC_GE, ARM_CC_LT, ARM_CC_GT, ARM_CC_LE, ARM_CC_AL
    };
    
    if (insn->detail->arm.cc != ARM_CC_INVALID) {
        arm_cc old_cc = insn->detail->arm.cc;
        do {
            insn->detail->arm.cc = condition_codes[rand() % 15];
        } while (insn->detail->arm.cc == old_cc);
    }
}

void ApplyBitwiseOperationsToImmediate(cs_insn *instruction, unsigned int Seed) {
    if (instruction == NULL || instruction->detail == NULL || 
        instruction->detail->arm.op_count == 0) {
        return;
    }
    
    for (int i = 0; i < instruction->detail->arm.op_count; i++) {
        cs_arm_op *op = &instruction->detail->arm.operands[i];
        if (op->type == ARM_OP_IMM) {
            int32_t imm = op->imm;
            switch (rand_r(&Seed) % 3) {
                case 0: imm ^= (1 << (rand_r(&Seed) % 32)); break;
                case 1: imm &= (0xFFFFFFFF >> (rand_r(&Seed) % 16)); break;
                case 2: imm |= (1 << (rand_r(&Seed) % 32)); break;
            }
            op->imm = imm;
        }
    }
}

void MutateStackOperation(cs_insn *insn, unsigned int Seed) {
    if (!insn || !insn->detail) return;
    
    const char *stack_ops[] = {
        "push {r0-r7}",
        "pop {r0-r7}",
        "stmdb sp!, {r0-r3}",
        "ldmia sp!, {r0-r3}",
        "push {lr}",
        "pop {lr}"
    };
    
    if (strstr(insn->mnemonic, "push") || strstr(insn->mnemonic, "pop") ||
        strstr(insn->mnemonic, "stm") || strstr(insn->mnemonic, "ldm")) {
        snprintf(insn->mnemonic, CS_MNEMONIC_SIZE, "%s",
                stack_ops[rand_r(&Seed) % (sizeof(stack_ops)/sizeof(stack_ops[0]))]);
    }
}

void MutateBranchTarget(cs_insn *insn, unsigned int Seed) {
    if (!insn || !insn->detail) return;
    
    if (insn->id >= ARM_INS_B && insn->id <= ARM_INS_BLX) {
        uint32_t new_target = ADDRESS + (rand_r(&Seed) % 0x1000);
        char new_op_str[32];
        snprintf(new_op_str, sizeof(new_op_str), "#0x%x", new_target);
        strncpy(insn->op_str, new_op_str, sizeof(new_op_str));
    }
}

void MutateRegisters(cs_insn *insn, unsigned int Seed) {
    if (!insn || !insn->detail) return;
    
    cs_arm *arm = &insn->detail->arm;
    for (int i = 0; i < arm->op_count; i++) {
        if (arm->operands[i].type == ARM_OP_REG) {
            arm->operands[i].reg = ARM_REG_R0 + (rand_r(&Seed) % 12);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uc_err err;
    
    if (!initialized) {
        if (!outfile) {
            outfile = fopen("/dev/null", "w");
            if (!outfile) {
                printf("Failed opening /dev/null\n");
                abort();
            }
        }
        initialized = 1;
    }

    // Reset coverage tracking
    memset(coverage_map, 0, sizeof(coverage_map));
    unique_paths = 0;

    // Initialize emulator
    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        fprintf(outfile, "Failed on uc_open() with error: %u\n", err);
        return 0;
    }

    // Map multiple memory regions
    uc_mem_map(uc, ADDRESS, 4 * 1024 * 1024, UC_PROT_ALL);
    uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL);

    // Initialize stack
    uint32_t stack_top = STACK_ADDRESS + STACK_SIZE - 0x4;
    uc_reg_write(uc, UC_ARM_REG_SP, &stack_top);

    // Add code hook for coverage tracking
    uc_hook trace;
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // Write code to memory
    if (uc_mem_write(uc, ADDRESS, Data, Size)) {
        fprintf(outfile, "Failed to write emulation code to memory\n");
        uc_close(uc);
        return 0;
    }

    // Initialize registers
    uint32_t initial_regs[13] = {0};  // R0-R12
    for (int i = 0; i < 13; i++) {
        uc_reg_write(uc, UC_ARM_REG_R0 + i, &initial_regs[i]);
    }

    // Emulate code with timeout
    err = uc_emu_start(uc, ADDRESS, ADDRESS + Size, 0, 1000);
    if (err) {
        fprintf(outfile, "Error %u: %s\n", err, uc_strerror(err));
    }

    uc_close(uc);
    return 0;
}

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    if (!Data || Size < 4 || MaxSize < Size) return Size;

    csh cs_handle;
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_handle) != CS_ERR_OK) return Size;
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insn = NULL;
    size_t count = cs_disasm(cs_handle, Data, Size, ADDRESS, 0, &insn);
    if (count == 0) {
        cs_close(&cs_handle);
        return Size;
    }

    // Apply multiple mutations per iteration
    size_t num_mutations = (rand_r(&Seed) % 3) + 2; // Apply 2-4 mutations
    for (size_t m = 0; m < num_mutations && count > 0; m++) {
        size_t instruction_index = rand_r(&Seed) % count;
        cs_insn *target_insn = &insn[instruction_index];

        // Enhanced mutation strategy selection
        switch (rand_r(&Seed) % 12) {
            case 0: ReplaceWithSimilarInstruction(target_insn); break;
            case 1: AdjustMemoryDisplacement(target_insn, Seed); break;
            case 2: ModifyMemoryBaseOrIndex(target_insn, Seed); break;
            case 3: MutateConditionCode(target_insn); break;
            case 4: ApplyBitwiseOperationsToImmediate(target_insn, Seed); break;
            case 5: MutateStackOperation(target_insn, Seed); break;
            case 6: MutateBranchTarget(target_insn, Seed); break;
            case 7: MutateRegisters(target_insn, Seed); break;
            case 8: 
                MutateConditionCode(target_insn);
                MutateRegisters(target_insn, Seed);
                break;
            case 9:
                MutateStackOperation(target_insn, Seed);
                MutateBranchTarget(target_insn, Seed);
                break;
            case 10:
                AdjustMemoryDisplacement(target_insn, Seed);
                ModifyMemoryBaseOrIndex(target_insn, Seed);
                break;
            case 11:
                // Compound mutation
                MutateConditionCode(target_insn);
                MutateRegisters(target_insn, Seed);
                MutateBranchTarget(target_insn, Seed);
                break;
        }
    }


    // Reassemble with Keystone
    ks_engine *ks;
    if (ks_open(KS_ARCH_ARM, KS_MODE_ARM, &ks) != KS_ERR_OK) {
        cs_free(insn, count);
        cs_close(&cs_handle);
        return Size;
    }

    unsigned char *buffer = malloc(MaxSize);
    if (!buffer) {
        ks_close(ks);
        cs_free(insn, count);
        cs_close(&cs_handle);
        return Size;
    }

    size_t new_size = 0;
    for (size_t i = 0; i < count && new_size < MaxSize; i++) {
        char instruction_str[MAX_INSTRUCTION_STRING];
        
        // Build instruction string with mnemonic and operands
        if (insn[i].op_str && *insn[i].op_str) {
            snprintf(instruction_str, sizeof(instruction_str), "%s %s",
                    insn[i].mnemonic, insn[i].op_str);
        } else {
            snprintf(instruction_str, sizeof(instruction_str), "%s",
                    insn[i].mnemonic);
        }

        unsigned char *encoded;
        size_t encoded_size, encoded_count;
        
        if (ks_asm(ks, instruction_str, ADDRESS, &encoded, &encoded_size, &encoded_count) == KS_ERR_OK) {
            // Only copy if we have space
            if (new_size + encoded_size <= MaxSize) {
                memcpy(buffer + new_size, encoded, encoded_size);
                new_size += encoded_size;
            }
            ks_free(encoded);
        }
    }

    // If reassembly was successful, copy the new code back
    if (new_size > 0 && new_size <= MaxSize) {
        memcpy(Data, buffer, new_size);
    } else {
        new_size = Size; // Keep original size if reassembly failed
    }

    // Cleanup
    free(buffer);
    ks_close(ks);
    cs_free(insn, count);
    cs_close(&cs_handle);

    return new_size;
}

// Optional: Add error handling helper function
static void handle_error(const char *message, cs_insn *insn, size_t count, 
                        csh cs_handle, ks_engine *ks, unsigned char *buffer) {
    if (buffer) free(buffer);
    if (insn) cs_free(insn, count);
    if (cs_handle) cs_close(&cs_handle);
    if (ks) ks_close(ks);
    fprintf(stderr, "Error: %s\n", message);
}