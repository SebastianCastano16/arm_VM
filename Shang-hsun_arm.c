#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/termios.h>
#include <sys/mman.h>

enum
{
    R0 = 0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    PC,     /* program counter */
    CPSR,   /* Current Program Status Register */
    REG_COUNT
};

enum
{
    ADD = 0,    // addition
    SUB,        // subtraction
    AND,        // bitwise and
    MOV,        // move immediate
    MVN,        // bitwise not
    B,          // branch
    LDR,        // load register
    STR,        // store register
    SVC         // supervisor call
};

#define MEMORY_MAX 65536
uint32_t memory[MEMORY_MAX]; /* 65536 locations */
uint32_t reg[REG_COUNT];

struct termios original_tio;

void disable_input_buffering()
{
    tcgetattr(STDIN_FILENO, &original_tio);
    struct termios new_tio = original_tio;
    new_tio.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
}

void restore_input_buffering()
{
    tcsetattr(STDIN_FILENO, TCSANOW, &original_tio);
}

uint32_t check_key()
{
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    return select(1, &readfds, NULL, NULL, &timeout) != 0;
}

void handle_interrupt(int signal)
{
    restore_input_buffering();
    printf("\n");
    exit(-2);
}

uint32_t sign_extend(uint32_t x, int bit_count)
{
    if ((x >> (bit_count - 1)) & 1)
    {
        x |= (0xFFFFFFFF << bit_count);
    }
    return x;
}

void update_flags(uint32_t r)
{
    if (reg[r] == 0)
    {
        reg[CPSR] = (1 << 30); // Zero flag (Z)
    }
    else if ((reg[r] >> 31) & 1) // a 1 in the left-most bit indicates negative
    {
        reg[CPSR] = (1 << 31); // Negative flag (N)
    }
    else
    {
        reg[CPSR] = 0; // No flags set (P)
    }
}

void read_image_file(FILE *file)
{
    // Read the origin (starting memory address) from the file
    uint32_t origin;
    fread(&origin, sizeof(origin), 1, file);

    // Read the maximum file size so we only need one fread
    uint32_t max_read = MEMORY_MAX - origin;
    uint32_t *p = memory + origin;
    size_t read = fread(p, sizeof(uint32_t), max_read, file);

    // No need to swap endianness in ARM architecture
}

int read_image(const char *image_path)
{
    FILE *file = fopen(image_path, "rb");
    if (!file)
    {
        return 0;
    }

    read_image_file(file);
    fclose(file);
    return 1;
}

void mem_write(uint32_t address, uint32_t val)
{
    memory[address] = val;
}

uint32_t mem_read(uint32_t address)
{
    if (address == 0xFF00)
    {
        if (check_key())
        {
            memory[0xFF00] = (1 << 31);
            memory[0xFF04] = getchar();
        }
        else
        {
            memory[0xFF00] = 0;
        }
    }
    return memory[address];
}

int main(int argc, const char *argv[])
{
    if (argc < 2)
    {
        /* show usage string */
        printf("arm [image-file1] ...\n");
        exit(2);
    }

    for (int j = 1; j < argc; ++j)
    {
        if (!read_image(argv[j]))
        {
            printf("failed to load image: %s\n", argv[j]);
            exit(1);
        }
    }
    signal(SIGINT, handle_interrupt);
    disable_input_buffering();

    /* since exactly one condition flag should be set at any given time, set the Z flag */
    reg[CPSR] = (1 << 30); // Zero flag (Z)

    /* set the PC to starting position */
    /* 0x3000 is the default */
    enum
    {
        PC_START = 0x3000
    };
    reg[PC] = PC_START;

    int running = 1;
    while (running)
    {
        /* FETCH */
        // Initialize the program counter
        uint32_t pc = reg[PC];

        // Read the instruction from memory at the address pointed by the program counter
        uint32_t instr = mem_read(pc);

        // Extract the opcode, register operands, and immediate value (if applicable)
        uint32_t op = (instr >> 24) & 0xFF;
        uint32_t rd = (instr >> 16) & 0xFF;
        uint32_t rn = (instr >> 8) & 0xFF;
        uint32_t rm = instr & 0xFF;
        uint32_t imm = instr & 0xFFFF;

        switch (op)
        {
        case ADD:
            reg[rd] = reg[rn] + reg[rm];
            update_flags(rd);
            break;

        case SUB:
            reg[rd] = reg[rn] - reg[rm];
            update_flags(rd);
            break;

        case AND:
            reg[rd] = reg[rn] & reg[rm];
            update_flags(rd);
            break;

        case MOV:
            reg[rd] = imm;
            update_flags(rd);
            break;

        case MVN:
            reg[rd] = ~reg[rm];
            update_flags(rd);
            break;

        case B:
            {
                uint32_t offset = instr & 0xFFFFFF;
                uint32_t cond_flag = (instr >> 28) & 0xF;
                int32_t sign_extended_offset = ((offset & 0x800000) ? (offset | 0xFF000000) : offset) << 2;

                if (cond_flag == 0xE || // Unconditional branch
                    (cond_flag == 0x0 && (reg[CPSR] & (1 << 30)))) // Branch if Z flag is set
                {
                    reg[PC] += sign_extended_offset;
                }
            }
            break;

        case LDR:
            {
                uint32_t offset = instr & 0xFFF;
                uint32_t address = reg[rn] + offset;
                reg[rd] = mem_read(address);
                update_flags(rd);
            }
            break;

        case STR:
            {
                uint32_t offset = instr & 0xFFF;
                uint32_t address = reg[rn] + offset;
                mem_write(address, reg[rd]);
            }
            break;

        case SVC:
            {
                uint32_t code = instr & 0xFF;
                switch (code)
                {
                case 0x25:
                    // Code for a system call to read a character
                    reg[R0] = (uint32_t)getchar();
                    break;
                case 0x22:
                    // Code for a system call to write a character
                    putc((char)reg[R0], stdout);
                    fflush(stdout);
                    break;
                case 0x27:
                    // Code for a system call to halt the program
                    running = 0;
                    break;
                default:
                    // Unsupported system call code
                    printf("Unsupported SVC instruction: 0x%02X\n", code);
                    break;
                }
            }
            break;

        default:
            printf("Invalid opcode: 0x%02X\n", op);
            break;
        }

        // Update the program counter
        reg[PC] += 4;
    }
    restore_input_buffering();
    return 0;
}


   