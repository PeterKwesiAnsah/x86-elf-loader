#define _GNU_SOURCE

#include "elf.h"
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include "auxvec.h"

#define MIN_ARG_COUNT 2
#define PROCESS_ABI_HIGHEST_ADDR ((Elf64_Addr *)0x00007fffffffffff)
#define PROCESS_ABI_TEXT_SEG_ADDR 0x0000000000400000

typedef struct
{
    int argc;
    int envc;
    Elf64_Addr *sp;
    __uint8_t *envp;
    __int8_t *argp;
    Elf64_Addr *argv;
} Usr_bckd_stck;

typedef struct
{
    Elf64_Addr sysinfo_ehdr;
    Elf64_Addr random;
} loader_auxv_t;

loader_auxv_t get_loader_auxv(void)
{
    loader_auxv_t result = {0};
    FILE *f = fopen("/proc/self/auxv", "rb");
    if (!f)
        return result;

    auxv_t auxv;
    while (fread(&auxv, sizeof(auxv), 1, f) == 1)
    {
        if (auxv.a_type == AT_SYSINFO_EHDR)
            result.sysinfo_ehdr = auxv.a_un.a_val;
        else if (auxv.a_type == AT_RANDOM)
            result.random = auxv.a_un.a_val;
        else if (auxv.a_type == AT_NULL)
            break;
    }
    fclose(f);
    return result;
}

static int elf_pflags_to_mmap_prot(int p_flags)
{
    int prot = 0;

    if (p_flags & PF_R)
        prot |= PROT_READ;
    if (p_flags & PF_W)
        prot |= PROT_WRITE;
    if (p_flags & PF_X)
        prot |= PROT_EXEC;

    return prot;
}
// function used to load executable files, shared objects like program interp
void *LoadET(void *s_addr, int fd, size_t page_size, char **interpath)
{
    off_t fsize = lseek(fd, 0, SEEK_END);
    __uint8_t *addr = mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (addr == MAP_FAILED)
    {
        perror("mmap failed creating a mapping for the entire object file");
        return NULL;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)addr;
    Elf64_Phdr *pht_start = (Elf64_Phdr *)(addr + ehdr->e_phoff);

    Elf64_Addr max_vaddr = 0;
    Elf64_Addr min_vaddr = ~0UL;
    size_t loadsegmmap_len = 0;
    Elf64_Addr pbrk = 0;

    for (int pht_i = 0; pht_i < ehdr->e_phnum; pht_i++)
    {
        if (pht_start[pht_i].p_type == PT_INTERP && interpath)
        {
            *interpath = strdup(addr + pht_start[pht_i].p_offset);
        }
        else if (pht_start[pht_i].p_type == PT_LOAD)
        {
            if (pht_start[pht_i].p_vaddr > max_vaddr)
            {
                max_vaddr = pht_start[pht_i].p_vaddr + pht_start[pht_i].p_memsz;
            }

            if (pht_start[pht_i].p_vaddr < min_vaddr)
            {
                min_vaddr = pht_start[pht_i].p_vaddr;
            }
        }
        // else if (pht_start[pht_i].p_type == PT_GNU_STACK){
        // check to add PROT_EXEC to the stack segment
        // }
    }

    loadsegmmap_len = max_vaddr - (min_vaddr & ~15);

    // now we reserve region
    __uint8_t *segs_addr = mmap(s_addr, loadsegmmap_len, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (segs_addr == MAP_FAILED)
    {
        perror("mmap failed reserving memory region");
        return NULL;
    }
    // load bias for ET_EXEC is 0
    __uint8_t *baddr = segs_addr - (min_vaddr & ~(page_size - 1));
    // usually for PIE, min_vaddr is 0 so the load bias is the same as the address of the loaded segement
    // TODO; We can handle non PIE, as the loader process since is PIE, the linux kernel chooses  0x555555554aaa + ASLR offset for the text segment

    for (int pht_i = 0; pht_i < ehdr->e_phnum; pht_i++)
    {
        if (pht_start[pht_i].p_type == PT_LOAD)
        {
            Elf64_Off relap_offset = pht_start[pht_i].p_offset & ~(page_size - 1);
            Elf64_Addr relap_vadress = pht_start[pht_i].p_vaddr & ~(page_size - 1);

            size_t size = (pht_start[pht_i].p_vaddr % page_size) + pht_start[pht_i].p_filesz;

            memcpy(baddr + relap_vadress, addr + relap_offset, size);
            int status = mprotect(baddr + relap_vadress, pht_start[pht_i].p_vaddr % page_size + pht_start[pht_i].p_memsz, elf_pflags_to_mmap_prot(pht_start[pht_i].p_flags));
            if (status == -1)
            {
                perror("mprotect failed when setting prots for individual load segments");
                return NULL;
            }
            // baddr + pht_start[pht_i].p_vaddr + pht_start[pht_i].p_memsz; is brk
        }
    }

    close(fd);
    munmap(addr, fsize);
    return baddr;
}

// Usage ./loader <path-to-elf-file> [CLI args to be passed to during process
// execution of the program]
int main(int argc, char **args, char **envp)
{

    if (argc < MIN_ARG_COUNT)
        return 1;

    const char *elfpath = args[1];

    size_t page_size = sysconf(_SC_PAGE_SIZE);

    char *interpath = NULL;
    // returns the program memory image starting address
    void *main_baddr = LoadET((void *)PROCESS_ABI_TEXT_SEG_ADDR, open(elfpath, O_RDONLY), page_size, &interpath);
    if (main_baddr == NULL)
        return 1;
    Elf64_Ehdr *main_Ehdr = (Elf64_Ehdr *)main_baddr;

    // We assume the executable object file is associated with dynamic linking
    void *interp_baddr = LoadET(NULL, open(interpath, O_RDONLY), page_size, NULL);
    if (interp_baddr == NULL)
        return 1;

#define AUX_VEC_SIZE (AUX_VECTOR_SIZE * sizeof(auxv_t))
#define ITEMS_SIZE(count) (sizeof(Elf64_Addr) * count)

    struct rlimit lm;
    // limit for size of arguments strings and environmental variables
    getrlimit(RLIMIT_STACK, &lm);
    size_t stack_arg_size = lm.rlim_cur;

    // we skip the name of the main executable file
    char **t_args = args + 1;
    char **t_envp = envp;

    // create stack segment
    Elf64_Addr *user_space_stack_vm_end = PROCESS_ABI_HIGHEST_ADDR;
    Elf64_Addr *user_space_stack_vm_start = (Elf64_Addr *)((Elf64_Addr)PROCESS_ABI_HIGHEST_ADDR - stack_arg_size);

    user_space_stack_vm_start = mmap(user_space_stack_vm_start, stack_arg_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_GROWSDOWN | MAP_ANONYMOUS, -1, 0);
    if (user_space_stack_vm_start == MAP_FAILED)
    {
        perror("stack segment mapping failed");
        return 1;
    };

    user_space_stack_vm_end = (Elf64_Addr *)((unsigned long)user_space_stack_vm_start + stack_arg_size);
    char *new_args = (char *)user_space_stack_vm_end;

    size_t envc = 0;

    char *fn;

    // copy args
    while (*t_args)
    {
        size_t len = strlen(*t_args) + 1;
        // new_args values are used to build the array of argument strings
        new_args -= len;
        if (!fn)
        {
            fn = new_args;
        }
        memcpy(new_args, *t_args, len);
        t_args++;
    }
    // last arg
    char *new_user_argp = new_args;

    //  copy env
    while (*t_envp)
    {
        size_t len = strlen(*t_envp) + 1;
        // new_args values are used to build the array of environment variables
        new_args -= len;
        memcpy((void *)new_args, *t_envp, len);
        t_envp++;
        envc += 1;
    }
    // last env
    char *new_user_envp = new_args;

    Elf64_Addr *user_aux_vec = (Elf64_Addr *)(((Elf64_Addr)new_args - 15UL) & ~15UL);
    const size_t stck_len = argc + envc + 2 + AUX_VECTOR_SIZE;
    if (stck_len % 2 != 0)
    {
        // alignment padding
        *--user_aux_vec = 0UL;
    }

    // We create a fixed size auxillary vector for the elf program interpretor
#define NEW_AUX_VEC_ENT(a_type, a_val) \
    do                                 \
    {                                  \
        *--user_aux_vec = (a_val);     \
        *--user_aux_vec = (a_type);    \
    } while (0)

    NEW_AUX_VEC_ENT(AT_NULL, 0);
    NEW_AUX_VEC_ENT(AT_EXECFN, (Elf64_Addr)fn);
    NEW_AUX_VEC_ENT(AT_PAGESZ, page_size);
    NEW_AUX_VEC_ENT(AT_EXECFD, open(elfpath, O_RDONLY));
    NEW_AUX_VEC_ENT(AT_PHNUM, main_Ehdr->e_phnum);
    NEW_AUX_VEC_ENT(AT_BASE, (Elf64_Addr)interp_baddr);
    NEW_AUX_VEC_ENT(AT_ENTRY, (Elf64_Addr)main_baddr + main_Ehdr->e_entry);
    NEW_AUX_VEC_ENT(AT_PHENT, main_Ehdr->e_phentsize);
    NEW_AUX_VEC_ENT(AT_FLAGS, 0);

    NEW_AUX_VEC_ENT(AT_PHDR, (Elf64_Addr)main_baddr + main_Ehdr->e_phoff);

    loader_auxv_t l_auxv_t = get_loader_auxv();

    NEW_AUX_VEC_ENT(AT_RANDOM, (Elf64_Addr)l_auxv_t.random);
    NEW_AUX_VEC_ENT(AT_SYSINFO_EHDR, l_auxv_t.sysinfo_ehdr);

    Elf64_Addr *sp = user_aux_vec;
    int user_argc = argc - 1;

    *--sp = 0UL;

    int user_envc = envc;
    while (user_envc-- > 0)
    {
        *--sp = (Elf64_Addr)new_user_envp;
        size_t len = strlen(new_user_envp) + 1;
        new_user_envp += len;
    }

    *--sp = 0UL;
    while (user_argc-- > 0)
    {
        *--sp = (Elf64_Addr)new_user_argp;
        size_t len = strlen(new_user_argp) + 1;
        new_user_argp += len;
    }

    *--sp = argc - 1;

#undef PROCESS_ABI_HIGHEST_ADDR
#undef PROCESS_ABI_TEXT_SEG_ADDR
#undef RANDOM_BYTES_SIZE
#undef AUX_VEC_SIZE
#undef ITEMS_SIZE

    void (*entry_point)(void) = (void (*)(void))((unsigned long)
                                                     interp_baddr +
                                                 (((Elf64_Ehdr *)interp_baddr)->e_entry));

    register unsigned long sp_val asm("rax") = (unsigned long)sp;
    register unsigned long entry_val asm("r15") = (unsigned long)entry_point;

    __asm__ __volatile__(
        "mov %%rax, %%rsp\n" // set stack pointer
        "push %%r15\n"       // push entry point onto stack
        "xor %%rax, %%rax\n" // zero all registers
        "xor %%rbx, %%rbx\n"
        "xor %%rcx, %%rcx\n"
        "xor %%rdx, %%rdx\n"
        "xor %%rdi, %%rdi\n"
        "xor %%rsi, %%rsi\n"
        "xor %%rbp, %%rbp\n"
        "xor %%r9,  %%r9\n"
        "xor %%r10, %%r10\n"
        "xor %%r11, %%r11\n"
        "xor %%r12, %%r12\n"
        "xor %%r13, %%r13\n"
        "xor %%r14, %%r14\n"
        "xor %%r15, %%r15\n"
        "ret\n"
        :
        : "r"(sp_val), "r"(entry_val) // GCC sees the register variables
        : "memory");
}