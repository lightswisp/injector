#include <errno.h>
#define _GNU_SOURCE
#include <signal.h>
#include <linux/limits.h>
#include <libgen.h>
#include <stdarg.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <elf.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/inotify.h>
#include <sys/syscall.h>

#include <Zydis/Zydis.h>

#define LOG_MAX_BUFFER_SIZE      1024
#define LOG_MAX_TIME_BUFFER_SIZE 128
#define COLOR_START(x) "\033["x"m"
#define COLOR_END      "\033[0m"
#define RED            "31"
#define GREEN          "32" 
#define YELLOW         "33"
#define LOGGER_LOG(status, fmt, ...) logger_log(status, __func__, fmt __VA_OPT__(,) __VA_ARGS__)

enum log_status{
    LOG,
    WARNING,
    FATAL
};

typedef struct {
    ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH]; 
    size_t instruction_size;
} shellcode_block_t;

typedef struct{
    pid_t pid;
    char lib_path[PATH_MAX];
    char process_name[PATH_MAX];
    uintptr_t dlclose_addr;
    uintptr_t dlopen_addr;
    uintptr_t entry;
    uintptr_t handle;
} injection_ctx_t;

// global context
injection_ctx_t context;



void hexdump(const void *ptr, size_t buflen) {
    const unsigned char *buf = (const unsigned char*)ptr;
    size_t i, j;

    for (i = 0; i < buflen; i += 16) {
        // 1. Print the sample memory offset
        printf("%08zx  ", i);

        // 2. Print the hex values (16 bytes per line)
        for (j = 0; j < 16; j++) {
            if (i + j < buflen) {
                printf("%02x ", buf[i + j]);
            } else {
                printf("   "); // Padding for shorter lines
            }
            if (j == 7) {
                printf(" "); // Extra space after 8th byte for readability
            }
        }

        printf(" |");

        // 3. Print the readable ASCII characters
        for (j = 0; j < 16; j++) {
            if (i + j < buflen) {
                // If it is printable, show it; otherwise print a dot '.'
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
            } else {
                printf(" "); // Padding for shorter lines
            }
        }
        
        printf("|\n");
    }
}

void logger_log(enum log_status status, const char *func, const char *fmt, ...){
  char buffer[LOG_MAX_BUFFER_SIZE];
  char time_buffer[LOG_MAX_TIME_BUFFER_SIZE];
  time_t now;
  struct tm* tm;
  va_list args;

  now = time(NULL);
  tm  = localtime(&now);
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  strftime(time_buffer, sizeof(time_buffer), "%F %X", tm);
  switch (status) {
    case LOG:
        fprintf(stdout, COLOR_START(GREEN)"[LOG @ %s]"COLOR_START(GREEN)" %s:"COLOR_END" %s\n", time_buffer, func, buffer);
        break;
    case WARNING:
        fprintf(stdout, COLOR_START(GREEN)"[WARNING @ %s]"COLOR_START(YELLOW)" %s:"COLOR_END" %s\n", time_buffer, func, buffer);
        break;
    case FATAL:
        fprintf(stdout, COLOR_START(GREEN)"[FATAL @ %s]"COLOR_START(RED)" %s:"COLOR_END" %s\n", time_buffer, func, buffer);
        break;
  }
  va_end(args);
}

pid_t find_pid(const char *pname){
    DIR *dir;
    struct dirent *ent;
    char path[PATH_MAX];
    char comm[256];
    pid_t target_pid = -1;

    if ((dir = opendir("/proc")) == NULL) {
        LOGGER_LOG(FATAL, "failed to open /proc");
        return -1;
    }

    while ((ent = readdir(dir)) != NULL) {
        int is_pid = 1;
        for (int i = 0; ent->d_name[i] != '\0'; i++) {
            if (!isdigit((unsigned char)ent->d_name[i])) {
                is_pid = 0;
                break;
            }
        }

        if (is_pid) {
            snprintf(path, sizeof(path), "/proc/%s/comm", ent->d_name);
            FILE *fp = fopen(path, "r");
            if (fp != NULL) {
                if (fgets(comm, sizeof(comm), fp) != NULL) {
                    size_t len = strlen(comm);
                    if (len > 0 && comm[len - 1] == '\n') {
                        comm[len - 1] = '\0';
                    }

                    if (strcmp(comm, pname) == 0) {
                        target_pid = (pid_t)atoi(ent->d_name);
                        fclose(fp);
                        break; 
                    }
                }
                fclose(fp);
            }
        }
    }
    
    closedir(dir);
    return target_pid;
}

uintptr_t get_base(pid_t pid, const char *lib, bool exact){
    FILE *fd = NULL;
    uintptr_t base_addr = 0;
    char path[PATH_MAX] = {0};
    char maps_buf[1024];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    fd = fopen(path, "r");
    struct {
        uintptr_t a_s, a_e;
        char perms[5];
        uintptr_t offset;
        char dev[255];
        int inode;
        char pathname[PATH_MAX];
        bool has_path;
    } maps;

    while(fgets(maps_buf, sizeof(maps_buf), fd)){
        [[maybe_unused]] int n = sscanf(maps_buf, "%lx-%lx %4s %lx %254s %d %4095s", 
            &maps.a_s, 
            &maps.a_e, 
            maps.perms, 
            &maps.offset, 
            maps.dev, 
            &maps.inode, 
            maps.pathname);

        if(exact){
            const char *bname = basename(maps.pathname);
            if(bname == NULL) continue;
            if(strcmp(bname, lib) == 0){
                base_addr = maps.a_s;
                break;
            }
        }
        else{
            if(strstr(maps.pathname, lib) != NULL){
                base_addr = maps.a_s;
                break;
            }
        }
    }

    fclose(fd);
    return base_addr;
} 

uint8_t *read_memory(pid_t pid, uintptr_t addr, size_t size){
    uint8_t *buffer = malloc(size);
    if(buffer == NULL){
        LOGGER_LOG(FATAL, "error allocating memory!");
        return NULL;
    }
    LOGGER_LOG(LOG, "buffer @ %p", buffer);
    int64_t word = 0;

	for (size_t i=0; i < size; i+=sizeof(word)) {
        word = 0;
		if ((word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL)) == -1) {
            LOGGER_LOG(FATAL, "error reading process memory");
            return NULL;
		}
        memcpy(buffer + i, &word, sizeof(word));
	}
    return buffer;
}

bool write_memory(pid_t pid, uintptr_t addr, uint8_t *data, size_t size){
    uint64_t word = 0; 
    for(size_t i = 0; i < size; i+=sizeof(word)){
        memcpy(&word, data+i, sizeof(word));
        if (ptrace(PTRACE_POKETEXT, pid, addr + i, word) == -1) {;
            LOGGER_LOG(FATAL, "error writing to process memory");
            return false;
		}
    }
    return true;
}

uintptr_t align(uintptr_t len, size_t alignment) {
    return (len + alignment - 1) & ~(alignment - 1);
}

char *dup_pad(const char *str, size_t pad){
    char *new_buf = calloc(strlen(str) + pad, 1);
    if(new_buf == NULL){
        LOGGER_LOG(FATAL, "error allocating memory!");
        return NULL;
    }
    strcpy(new_buf, str);
    return new_buf;
}
ZyanU8 *generate_uninjection_shellcode(uintptr_t rsp, uintptr_t dlclose_addr, uintptr_t handle, ZyanUSize *shellcode_size){
    // mov rdi, handle
    // mov rax, dlclose_addr
    // sub rsp, stack_mod
    // call rax
    // int3
    // nop
    // nop 
    // nop
    ZydisEncoderRequest req; 
    ZyanU8 *shellcode = NULL;
    ZyanUSize temp_size = 0;
    size_t instructions = 8;
    size_t nop_sled_size = 0;

    uintptr_t stack_mod = rsp & 15; // mod(16)
    if(stack_mod != 0){
        LOGGER_LOG(WARNING, "warning! stack is misaligned");
    }

    LOGGER_LOG(LOG, "generated instructions: %lu", instructions);
    shellcode_block_t *blocks = calloc(instructions, instructions*sizeof(shellcode_block_t));
    if(blocks == NULL){
        LOGGER_LOG(FATAL, "error allocating memory!");
        goto end;
    }
    size_t current_block = 0;

    // mov rdi, handle
    memset(&req, 0, sizeof(req)); 
    req.mnemonic = ZYDIS_MNEMONIC_MOV; 
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
    req.operand_count = 2; 
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER; 
    req.operands[0].reg.value = ZYDIS_REGISTER_RDI; 
    req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE; 
    req.operands[1].imm.u = handle; 
    blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
    { 
        LOGGER_LOG(FATAL, "failed to encode mov instruction");
        goto end; 
    } 
    temp_size+=blocks[current_block].instruction_size;
    current_block++;

    // mov rax, dlclose_addr
    memset(&req, 0, sizeof(req)); 
    req.mnemonic = ZYDIS_MNEMONIC_MOV; 
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
    req.operand_count = 2; 
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER; 
    req.operands[0].reg.value = ZYDIS_REGISTER_RAX; 
    req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE; 
    req.operands[1].imm.u = dlclose_addr; 
    blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
    { 
        LOGGER_LOG(FATAL, "failed to encode mov instruction");
        goto end; 
    } 
    temp_size+=blocks[current_block].instruction_size;
    current_block++;

    // sub rsp, stack_mod
    memset(&req, 0, sizeof(req)); 
    req.mnemonic = ZYDIS_MNEMONIC_SUB; 
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
    req.operand_count = 2; 
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER; 
    req.operands[0].reg.value = ZYDIS_REGISTER_RSP; 
    req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE; 
    req.operands[1].imm.u = stack_mod; 
    blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
    { 
        LOGGER_LOG(FATAL, "failed to encode sub instruction");
        goto end; 
    } 
    temp_size+=blocks[current_block].instruction_size;
    current_block++;

    // call dlclose
    memset(&req, 0, sizeof(req)); 
    req.mnemonic = ZYDIS_MNEMONIC_CALL; 
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
    req.operand_count = 1; 
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER; 
    req.operands[0].reg.value = ZYDIS_REGISTER_RAX; 
    blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
    { 
        LOGGER_LOG(FATAL, "failed to eecode call instnuction");
        goto end; 
    } 
    temp_size+=blocks[current_block].instruction_size;
    current_block++;

    // int3
    memset(&req, 0, sizeof(req)); 
    req.mnemonic = ZYDIS_MNEMONIC_INT3; 
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
    req.operand_count = 0; 
    blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
    { 
        LOGGER_LOG(FATAL, "failed to encode int3 instruction");
        goto end; 
    } 
    temp_size+=blocks[current_block].instruction_size;
    current_block++;

    for(size_t i = 0; i < nop_sled_size; i++){
        memset(&req, 0, sizeof(req)); 
        req.mnemonic = ZYDIS_MNEMONIC_NOP; 
        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
        req.operand_count = 0; 
        blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
        if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
        { 
            LOGGER_LOG(FATAL, "failed to encode nop instruction");
            goto end; 
        } 
        temp_size+=blocks[current_block].instruction_size;
        current_block++;
    }

    // nop sled for ptrace write alignment, because we write in 8 bytes
    nop_sled_size = align(temp_size, sizeof(uint64_t)) - temp_size; 
    instructions += nop_sled_size;
    blocks = realloc(blocks, instructions*sizeof(shellcode_block_t));
    if(blocks == NULL){
        LOGGER_LOG(FATAL, "error reallocating memory!");
        goto end;
    }

    for(size_t i = 0; i < nop_sled_size; i++){
        memset(&req, 0, sizeof(req)); 
        req.mnemonic = ZYDIS_MNEMONIC_NOP; 
        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
        req.operand_count = 0; 
        blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
        if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
        { 
            LOGGER_LOG(FATAL, "failed to encode nop instruction");
            goto end; 
        } 
        temp_size+=blocks[current_block].instruction_size;
        current_block++;
    }

    assert(temp_size % 8 == 0 && "shellcode must be a multiple of 8 bytes");
    shellcode = malloc(temp_size);
    if(shellcode == NULL){
        LOGGER_LOG(FATAL, "error allocating memory!");
        goto end;
    }
    *shellcode_size = temp_size;
    size_t shellcode_offset = 0;
    for(size_t i = 0; i < instructions; i++){
        memcpy(shellcode + shellcode_offset, blocks[i].encoded_instruction, blocks[i].instruction_size);
        shellcode_offset += blocks[i].instruction_size;
    }

end:
    free(blocks);
    return shellcode;
}

ZyanU8 *generate_injection_shellcode(uintptr_t rsp, uintptr_t dlopen_addr, const char *lib, ZyanUSize *shellcode_size){
    // mov rbx, 0x6767676767676767 | =====> this part is dynamic
    // push rbx                    |
    // ...
    // mov rdi, rsp                | 
    // mov rsi, RTLD_NOW           |
    // mov rax, dlopen_addr        | =======> static instructions
    // sub rsp, stack_mod          |
    // call rax                    |
    // int3                        |

    ZydisEncoderRequest req; 
    ZyanU8 *shellcode = NULL;
    ZyanUSize temp_size = 0;
    size_t nop_sled_size = 0;
    size_t len = strlen(lib);
    // 8 byte alignment to chop the string 
    // because each mov instruction can hold 8 byte at max
    uintptr_t aligned = align(len, sizeof(uint64_t));
    // align it again by 16 bytes, because we need our stack to be aligned
    // x86-64 / ABI requires our stack to be aligned for simd ops
    // otherwise we will get segmentation fault
    // we assume that the stack is already aligned
    aligned = align(aligned, 16);

    uintptr_t stack_mod = rsp & 15; // mod(16)
    if(stack_mod != 0){
        LOGGER_LOG(WARNING, "warning! stack is misaligned");
    }

    size_t pad = aligned - len;
    char *padded = dup_pad(lib, pad);
    size_t static_instructions = 6;
    size_t instructions = (aligned/8)*2 + static_instructions;
    LOGGER_LOG(LOG, "generated instructions: %lu", instructions);
    shellcode_block_t *blocks = calloc(instructions, sizeof(shellcode_block_t));
    if(blocks == NULL){
        LOGGER_LOG(FATAL, "error allocating memory!");
        goto end;
    }
    size_t current_block = 0;

    for(int i = aligned-8; i >= 0; i-=8){

        uint64_t chunk = 0;
        memcpy(&chunk, padded+i, sizeof(chunk));
        memset(&req, 0, sizeof(req)); 
        
        req.mnemonic = ZYDIS_MNEMONIC_MOV; 
        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
        req.operand_count = 2; 
        req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER; 
        req.operands[0].reg.value = ZYDIS_REGISTER_RBX; 
        req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE; 
        // force 64bit operand
        req.operands[1].imm.u = 0x1122334455667788; 
        blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
        if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
        { 
            LOGGER_LOG(FATAL, "failed to encode mov instruction");
            goto end; 
        } 
        memcpy(blocks[current_block].encoded_instruction + 2, &chunk, sizeof(uint64_t));
        temp_size+=blocks[current_block].instruction_size;
        current_block++;

        memset(&req, 0, sizeof(req)); 
        req.mnemonic = ZYDIS_MNEMONIC_PUSH; 
        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
        req.operand_count = 1; 
        req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER; 
        req.operands[0].reg.value = ZYDIS_REGISTER_RBX; 
        blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
        if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
        { 
            LOGGER_LOG(FATAL, "failed to encode push instruction");
            goto end; 
        } 
        temp_size+=blocks[current_block].instruction_size;
        current_block++;
    }
    
    // mov rdi, rsp
    memset(&req, 0, sizeof(req)); 
    req.mnemonic = ZYDIS_MNEMONIC_MOV; 
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
    req.operand_count = 2; 
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER; 
    req.operands[0].reg.value = ZYDIS_REGISTER_RDI; 
    req.operands[1].type = ZYDIS_OPERAND_TYPE_REGISTER; 
    req.operands[1].reg.value = ZYDIS_REGISTER_RSP; 
    blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
    { 
        LOGGER_LOG(FATAL, "failed to encode mov instruction");
        goto end; 
    } 
    temp_size+=blocks[current_block].instruction_size;
    current_block++;

    // mov rsi, RTLD_NOW
    memset(&req, 0, sizeof(req)); 
    req.mnemonic = ZYDIS_MNEMONIC_MOV; 
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
    req.operand_count = 2; 
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER; 
    req.operands[0].reg.value = ZYDIS_REGISTER_RSI; 
    req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE; 
    req.operands[1].imm.u = RTLD_NOW; 
    blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
    { 
        LOGGER_LOG(FATAL, "failed to encode mov instruction");
        goto end; 
    } 
    temp_size+=blocks[current_block].instruction_size;
    current_block++;
    
    // mov rax, dlopen
    memset(&req, 0, sizeof(req)); 
    req.mnemonic = ZYDIS_MNEMONIC_MOV; 
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
    req.operand_count = 2; 
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER; 
    req.operands[0].reg.value = ZYDIS_REGISTER_RAX; 
    req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE; 
    req.operands[1].imm.u = dlopen_addr; 
    blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
    { 
        LOGGER_LOG(FATAL, "failed to encode mov instruction");
        goto end; 
    } 
    temp_size+=blocks[current_block].instruction_size;
    current_block++;
    
    // sub rsp, stack_mod
    memset(&req, 0, sizeof(req)); 
    req.mnemonic = ZYDIS_MNEMONIC_SUB; 
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
    req.operand_count = 2; 
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER; 
    req.operands[0].reg.value = ZYDIS_REGISTER_RSP; 
    req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE; 
    req.operands[1].imm.u = stack_mod; 
    blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
    { 
        LOGGER_LOG(FATAL, "failed to encode sub instruction");
        goto end; 
    } 
    temp_size+=blocks[current_block].instruction_size;
    current_block++;
    
    // call dlopen
    memset(&req, 0, sizeof(req)); 
    req.mnemonic = ZYDIS_MNEMONIC_CALL; 
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
    req.operand_count = 1; 
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER; 
    req.operands[0].reg.value = ZYDIS_REGISTER_RAX; 
    blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
    { 
        LOGGER_LOG(FATAL, "failed to encode call instruction");
        goto end; 
    } 
    temp_size+=blocks[current_block].instruction_size;
    current_block++;

    // int3
    memset(&req, 0, sizeof(req)); 
    req.mnemonic = ZYDIS_MNEMONIC_INT3; 
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
    req.operand_count = 0; 
    blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
    { 
        LOGGER_LOG(FATAL, "failed to encode int3 instruction");
        goto end; 
    } 
    temp_size+=blocks[current_block].instruction_size;
    current_block++;

    // nop sled for ptrace write alignment, because we write in 8 bytes
    nop_sled_size = align(temp_size, sizeof(uint64_t)) - temp_size; 
    instructions += nop_sled_size;
    blocks = realloc(blocks, instructions*sizeof(shellcode_block_t));
    if(blocks == NULL){
        LOGGER_LOG(FATAL, "error reallocating memory!");
        goto end;
    }

    for(size_t i = 0; i < nop_sled_size; i++){
        memset(&req, 0, sizeof(req)); 
        req.mnemonic = ZYDIS_MNEMONIC_NOP; 
        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64; 
        req.operand_count = 0; 
        blocks[current_block].instruction_size = ZYDIS_MAX_INSTRUCTION_LENGTH;
        if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, blocks[current_block].encoded_instruction, &blocks[current_block].instruction_size))) 
        { 
            LOGGER_LOG(FATAL, "failed to encode nop instruction");
            goto end; 
        } 
        temp_size+=blocks[current_block].instruction_size;
        current_block++;
    }

    assert(temp_size % 8 == 0 && "shellcode must be a multiple of 8 bytes");

    shellcode = malloc(temp_size);
    if(shellcode == NULL){
        LOGGER_LOG(FATAL, "error allocating memory!");
        goto end;
    }
    *shellcode_size = temp_size;
    size_t shellcode_offset = 0;
    for(size_t i = 0; i < instructions; i++){
        memcpy(shellcode + shellcode_offset, blocks[i].encoded_instruction, blocks[i].instruction_size);
        shellcode_offset += blocks[i].instruction_size;
    }

end:
    free(padded);
    free(blocks);
    return shellcode;
}


bool handle_injection_trap(pid_t pid, struct user_regs_struct *old_regs, uintptr_t old_entry, uint8_t *backup_buffer, size_t size){
    struct user_regs_struct regs;
    while(true){
        int status;
        pid_t tid = waitpid(-1, &status, __WALL);
        if(tid == -1){
            LOGGER_LOG(FATAL, "waitpid error");
            return false;
        }

        if(WIFSTOPPED(status)){
            int signal = WSTOPSIG(status);
            if(signal == SIGTRAP){
                LOGGER_LOG(LOG, "received trap from %d", tid);
                if(tid != pid){
                    continue;
                } 
                ptrace(PTRACE_GETREGS, tid, NULL, &regs);

                context.handle = regs.rax;
                if(context.handle == 0){
                    LOGGER_LOG(FATAL, "dlopen failed, handle is NULL");
                    return false;
                }
                // restore instructions
                write_memory(tid, old_entry, backup_buffer, size);
                LOGGER_LOG(LOG, "restoring registers state");
                if(ptrace(PTRACE_SETREGS, tid, NULL, old_regs) == -1){
                    LOGGER_LOG(FATAL, "failed to set registers");
                    return false;
                }
                break;
            }
        }
    }
    return true;
}

bool handle_uninjection_trap(pid_t pid, struct user_regs_struct *old_regs, uintptr_t old_entry, uint8_t *backup_buffer, size_t size){
    struct user_regs_struct regs;
    while(true){
        int status;
        pid_t tid = waitpid(-1, &status, __WALL);
        if(tid == -1){
            LOGGER_LOG(FATAL, "waitpid error");
            return false;
        }

        if(WIFSTOPPED(status)){
            int signal = WSTOPSIG(status);
            if(signal == SIGTRAP){
                LOGGER_LOG(LOG, "received trap from %d", tid);
                if(tid != pid){
                    continue;
                } 
                ptrace(PTRACE_GETREGS, tid, NULL, &regs);

                int dlclose_status = regs.rax;
                if(dlclose_status != 0){
                    LOGGER_LOG(FATAL, "dlclose failed");
                    return false;
                }
                // restore instructions
                write_memory(tid, old_entry, backup_buffer, size);
                LOGGER_LOG(LOG, "restoring registers state");
                if(ptrace(PTRACE_SETREGS, tid, NULL, old_regs) == -1){
                    LOGGER_LOG(FATAL, "failed to set registers");
                    return false;
                }
                break;
            }
        }
    }
    return true;
}

bool inject(){
    LOGGER_LOG(LOG, "injecting...");
    int success = false;

    uint8_t *backup_buffer = NULL;
    Elf64_Ehdr *external_elf_header = NULL;
    ZyanU8 *shellcode = NULL;

    struct user_regs_struct old_regs, regs;
    if (ptrace(PTRACE_ATTACH, context.pid, NULL, NULL) < 0) {
        LOGGER_LOG(FATAL, "attach failed");
        goto end;
    }
    waitpid(context.pid, NULL, 0);
    ptrace(PTRACE_GETREGS, context.pid, NULL, &regs); 
    ptrace(PTRACE_GETREGS, context.pid, NULL, &old_regs); 
    LOGGER_LOG(LOG, "attached to %d", context.pid);

    uintptr_t dlopen_offset, dlclose_offset;
    uintptr_t external_process_base = get_base(context.pid, context.process_name, true);
    if(external_process_base == 0){
        LOGGER_LOG(FATAL, "unable to get %d base", context.pid);
        goto end;
    }
    external_elf_header = (Elf64_Ehdr*)read_memory(context.pid, external_process_base, sizeof(Elf64_Ehdr));
    if(external_elf_header == NULL){
        LOGGER_LOG(FATAL, "unable read elf header of %d", context.pid);
        goto end;
    }
    uintptr_t external_module_base = get_base(context.pid, "libc.so", false);
    if(external_module_base == 0){
        LOGGER_LOG(FATAL, "unable to get external libc.so base");
        goto end;
    }

    LOGGER_LOG(LOG, "external libc.so base: %p", (void*)external_module_base);

    uintptr_t local_module_base = get_base(getpid(), "libc.so", false);
    if(local_module_base == 0){
        LOGGER_LOG(FATAL, "unable to get local libc.so base");
        goto end;
    }

    if(external_elf_header->e_ident[0] != ELFMAG0 && 
       external_elf_header->e_ident[1] != ELFMAG1 &&
       external_elf_header->e_ident[2] != ELFMAG2 && 
       external_elf_header->e_ident[3] != ELFMAG3)
    {
        LOGGER_LOG(FATAL, "elf identification failed");
        goto end;
    }

    /*
     *  There are two special pseudo-handles that may be specified in
       handle:

       RTLD_DEFAULT
              Find the first occurrence of the desired symbol using the
              default shared object search order.  The search will
              include global symbols in the executable and its
              dependencies, as well as symbols in shared objects that
              were dynamically loaded with the RTLD_GLOBAL flag.

       RTLD_NEXT
              Find the next occurrence of the desired symbol in the
              search order after the current object.  This allows one to
              provide a wrapper around a function in another shared
              object, so that, for example, the definition of a function
              in a preloaded shared object (see LD_PRELOAD in ld.so(8))
              can find and invoke the "real" function provided in another
              shared object (or for that matter, the "next" definition of
              the function in cases where there are multiple layers of
              preloading).

      */
    // TODO
    // this is unreliable, we should parse elf file by ourselves
    dlopen_offset  = (uintptr_t)dlsym(RTLD_NEXT, "dlopen")  - local_module_base;
    dlclose_offset = (uintptr_t)dlsym(RTLD_NEXT, "dlclose") - local_module_base;

    LOGGER_LOG(LOG, "dlopen offset: %p", (void*)dlopen_offset);
    LOGGER_LOG(LOG, "dlclose offset: %p",(void*)dlclose_offset);
    uintptr_t dlopen_addr = external_module_base + dlopen_offset;

    // saving for later use
    context.dlclose_addr = external_module_base + dlclose_offset;
    context.dlopen_addr  = dlopen_addr;

    LOGGER_LOG(LOG, "dlopen memory address in %d: %p", context.pid, (void*)context.dlopen_addr);
    LOGGER_LOG(LOG, "dlclose memory address in %d: %p", context.pid, (void*)context.dlclose_addr);
    
    // now let's read the entry point addr
    uintptr_t external_entry = external_elf_header->e_entry + external_process_base;
    context.entry = external_entry;
    LOGGER_LOG(LOG, "external entry point: 0x%lx", external_entry);

    ZyanUSize shellcode_size = 0;
    shellcode = generate_injection_shellcode(regs.rsp, dlopen_addr, context.lib_path, &shellcode_size);
    if(shellcode == NULL){
        LOGGER_LOG(FATAL, "shellcode generation failed");
        goto end;
    }

    // preserving instructions, reading from entry point
    backup_buffer = read_memory(context.pid, context.entry, shellcode_size);
    if(backup_buffer == NULL){
        LOGGER_LOG(FATAL, "failed to backup memory!");
        goto end;
    }

    // write shellcode
    if(!write_memory(context.pid, context.entry, shellcode, shellcode_size)){
        LOGGER_LOG(FATAL, "failed to write memory at entry point");
        goto end;
    }

    regs.rip = context.entry;
    // sometimes rip is substracted by 2 bytes which can cause segfaults
    // https://gist.github.com/zhangyoufu/86910448ec92c7eca7e39186b79c98c2
    regs.rax = -1;
    ptrace(PTRACE_SETREGS, context.pid, NULL, &regs);
    ptrace(PTRACE_CONT, context.pid, NULL, NULL);
    if(!handle_injection_trap(context.pid, &old_regs, context.entry, backup_buffer, shellcode_size))
        goto end;

    LOGGER_LOG(LOG, "detaching...");
    if(ptrace(PTRACE_DETACH, context.pid, NULL, NULL) == -1){
        LOGGER_LOG(FATAL, "ptrace detach failed, errno: %d", errno);
        goto end;
    } 

    success = true;

end:
    free(external_elf_header);
    free(backup_buffer);
    free(shellcode);
    return success;
}


bool uninject(){
    LOGGER_LOG(LOG, "uninjecting...");
    int success = false;
    uint8_t *backup_buffer = NULL;
    ZyanU8 *shellcode = NULL;

    struct user_regs_struct old_regs, regs;
    if (ptrace(PTRACE_ATTACH, context.pid, NULL, NULL) < 0) {
        LOGGER_LOG(FATAL, "attach failed");
        goto end;
    }
    waitpid(context.pid, NULL, 0);
    ptrace(PTRACE_GETREGS, context.pid, NULL, &regs); 
    ptrace(PTRACE_GETREGS, context.pid, NULL, &old_regs); 
    LOGGER_LOG(LOG, "attached to %d", context.pid);

    ZyanUSize shellcode_size = 0;
    shellcode = generate_uninjection_shellcode(regs.rsp, context.dlclose_addr, context.handle, &shellcode_size);
    if(shellcode == NULL){
        LOGGER_LOG(FATAL, "shellcode generation failed");
        goto end;
    }

    LOGGER_LOG(LOG, "shellcode @ %p", shellcode);
    hexdump(shellcode, shellcode_size);

    // preserving instructions, reading from entry point
    backup_buffer = read_memory(context.pid, context.entry, shellcode_size);
    if(backup_buffer == NULL){
        LOGGER_LOG(FATAL, "failed to backup memory!");
        goto end;
    }

    // write shellcode
    if(!write_memory(context.pid, context.entry, shellcode, shellcode_size)){
        LOGGER_LOG(FATAL, "failed to write memory at entry point");
        goto end;
    }

    regs.rip = context.entry;
    regs.rax = -1;
    ptrace(PTRACE_SETREGS, context.pid, NULL, &regs);
    ptrace(PTRACE_CONT, context.pid, NULL, NULL);
    if(!handle_uninjection_trap(context.pid, &old_regs, context.entry, backup_buffer, shellcode_size))
        goto end;

    LOGGER_LOG(LOG, "detaching...");

    if(ptrace(PTRACE_DETACH, context.pid, NULL, NULL) == -1){
        LOGGER_LOG(FATAL, "ptrace detach failed, errno: %d", errno);
        goto end;
    } 
    success = true;

end:
    free(backup_buffer);
    free(shellcode);
    return success;
}

void handle_sigint([[maybe_unused]] int signal){
    LOGGER_LOG(LOG, "ctrl+c is pressed...");
    if(uninject())
        exit(EXIT_SUCCESS);
    exit(EXIT_FAILURE);
}

void init_context(pid_t pid, const char *lib_path, const char *process_name){
    memset(&context, 0, sizeof(injection_ctx_t));
    context.pid = pid;
    size_t lib_path_len = strlen(lib_path);
    size_t process_name_len = strlen(process_name);
    assert(lib_path_len < sizeof(context.lib_path));
    assert(process_name_len < sizeof(context.process_name));
    memcpy(context.lib_path, lib_path, lib_path_len);
    memcpy(context.process_name, process_name, process_name_len);
}

bool read_logs(const char *path){
    #define MAX_EV 512
    #define EV_BUF_SIZE (MAX_EV*(sizeof(struct inotify_event) + NAME_MAX + 1))
    
    int status = false;
    char log_buf[1024];
    char ev_buf[EV_BUF_SIZE];
    FILE *log_fd = fopen(path, "r");
    if(log_fd == NULL){
        LOGGER_LOG(FATAL, "failed to open logs");
        return false;
    }

    int fd = inotify_init();
    if (fd == -1) {
        LOGGER_LOG(FATAL, "inotify init failed");
        goto end_1;
    }

    int wd = inotify_add_watch(fd, path, IN_MODIFY);
    if (wd == -1) {
        LOGGER_LOG(FATAL, "inotify add watch failed");
        goto end_2;
    }
    while(true){
        int r = read(fd, ev_buf, EV_BUF_SIZE);
        if(r == -1){
            LOGGER_LOG(FATAL, "inotify read failed");
            goto end_3;
        }
        while(fread(log_buf, 1, sizeof(log_buf) - 1, log_fd) > 0){
            fprintf(stdout, "%s", log_buf);
        } 
        clearerr(log_fd); 
        memset(log_buf, 0, sizeof(log_buf));
    }
    status = true;

end_3:
    inotify_rm_watch(fd, wd);
end_2:
    close(fd);
end_1:
    fclose(log_fd);
    return status;
}


static void print_usage(const char *prog)
{
    fprintf(stdout, "Usage: %s -p <process_name> -l <library.so> -x <log path>\n", prog);
    fprintf(stdout, "\nOptions:\n");
    fprintf(stdout, "  -p <name>    Target process name\n");
    fprintf(stdout, "  -l <path>    Path to .so library\n");
    fprintf(stdout, "  -x <path>    Path to log file\n");
    fprintf(stdout, "  -h           Show this help message\n");
}

int main(int argc, char **argv){

    char *process_name = NULL;
    char *lib_path     = NULL;
    char *log_path     = NULL;
    pid_t pid          = -1;
    int exit_status    = EXIT_FAILURE;
    int opt;

    while ((opt = getopt(argc, argv, "p:l:x:h")) != -1) {
      switch (opt) {
      case 'p':
          process_name = optarg;
          break;

      case 'l':
          lib_path = optarg;
          break;

      case 'x':
          log_path = optarg;
          break;

      case 'h':
          print_usage(argv[0]);
          return exit_status;

      default:
          print_usage(argv[0]);
          return exit_status;
      }
    }

    if(lib_path == NULL){
      LOGGER_LOG(FATAL, ".so path is missing");
      print_usage(argv[0]);
      return exit_status;
    }

    if(process_name == NULL){
      LOGGER_LOG(FATAL, "process name is missing");
      print_usage(argv[0]);
      return exit_status;
    }

    // handle ctrl+c
    struct sigaction act;
    act.sa_handler = handle_sigint;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, NULL);

    if(geteuid() != 0){
        LOGGER_LOG(WARNING, "run as root please");
        goto end;
    }

    char *absolute_path = realpath(lib_path, NULL);
    LOGGER_LOG(LOG, "absolute path: %s", absolute_path);

    pid = find_pid(process_name);
    if(pid == -1){
        LOGGER_LOG(FATAL, "unable to find pid of %s", process_name);
        goto end;
    }

    init_context(pid, absolute_path, process_name);

    LOGGER_LOG(LOG, "process pid: %d", pid);
    if(!inject()){
        LOGGER_LOG(FATAL, "injection failed");
        goto end;
    }

    LOGGER_LOG(LOG, "dlopen handle: %p", context.handle);
    LOGGER_LOG(LOG, "To uninject, press ctrl+c");

    // tail the log file output 
    if(log_path){
      if(!read_logs(log_path))
          goto end;
    }

    exit_status = EXIT_SUCCESS;
end:
    return exit_status;
}
