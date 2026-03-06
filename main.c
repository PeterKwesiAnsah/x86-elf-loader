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

typedef struct
{
  int argc;
  int envc;
  Elf64_Addr *sp;
  __uint8_t *envp;
  __int8_t *argp;
  Elf64_Addr *argv;
} Usr_bckd_stck;

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
void *LoadET(int fd, size_t page_size, char **interpath)
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

  int pht_i = 0;
  for (; pht_i < ehdr->e_phnum; pht_i++)
  {
    if (pht_start[pht_i].p_type == PT_INTERP && interpath)
    {
      *interpath = strdup(addr + pht_start[pht_i].p_offset);
    }
    else if (pht_start[pht_i].p_type == PT_LOAD)
    {
      loadsegmmap_len += ((pht_start[pht_i].p_memsz + (page_size - 1)) & ~(page_size - 1));
      if (pht_start[pht_i].p_vaddr > max_vaddr)
      {
        max_vaddr = pht_start[pht_i].p_vaddr;
      }

      if (pht_start[pht_i].p_vaddr < min_vaddr)
      {
        min_vaddr = pht_start[pht_i].p_vaddr;
      }
    }
    // else if (pht_start[pht_i].p_type == PT_GNU_STACK){
    // check to add PROT_EXEC to stack page
    // }
  }

  assert(loadsegmmap_len % page_size == 0);

  // now we reserve region
  __uint8_t *segs_addr = mmap(NULL, loadsegmmap_len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (segs_addr == MAP_FAILED)
  {
    perror("mmap failed reserving memory region");
    return NULL;
  }

  assert(min_vaddr == 0UL);

  __uint8_t *baddr = segs_addr - (min_vaddr & ~(page_size - 1));
  pht_i = 0;
  for (; pht_i < ehdr->e_phnum; pht_i++)
  {
    if (pht_start[pht_i].p_type == PT_LOAD)
    {
      Elf64_Off relap_offset = pht_start[pht_i].p_offset & ~(page_size - 1);
      Elf64_Addr relap_vadress = pht_start[pht_i].p_vaddr & ~(page_size - 1);
      segs_addr = mmap(baddr + relap_vadress, (pht_start[pht_i].p_vaddr % page_size) + pht_start[pht_i].p_filesz, elf_pflags_to_mmap_prot(pht_start[pht_i].p_flags), MAP_PRIVATE | MAP_FIXED, fd, relap_offset);
      if (segs_addr == MAP_FAILED)
      {
        perror("mmap failed mapping individual load segments");
        return NULL;
      }
      // heap segment, last segment with the tailed-backed .bss
      // brk is set right on top of .bss
      if (pht_start[pht_i].p_memsz > pht_start[pht_i].p_filesz)
      {
        size_t bss_size = pht_start[pht_i].p_memsz - pht_start[pht_i].p_filesz;
        memset(baddr + pht_start[pht_i].p_vaddr + pht_start[pht_i].p_filesz, '\0', bss_size);
        pbrk = (Elf64_Addr)baddr + pht_start[pht_i].p_vaddr + pht_start[pht_i].p_filesz + bss_size;
      }
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
  void *main_baddr = LoadET(open(elfpath, O_RDONLY), page_size, &interpath);
  if (main_baddr == NULL)
    return 1;
  Elf64_Ehdr *main_Ehdr = (Elf64_Ehdr *)main_baddr;

  // We assume the executable object file is associated with dynamic linking
  void *interp_baddr = LoadET(open(interpath, O_RDONLY), page_size, NULL);
  if (interp_baddr == NULL)
    return 1;

#define PROCESS_ABI_HIGHEST_ADDR ((Elf64_Addr *)0x00007fffffffffff)
#define PROCESS_ABI_TEXT_SEG_ADDR 0x400000
#define RANDOM_BYTES_SIZE 16
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

  // TODO: Update Stack length
  user_space_stack_vm_start = mmap(user_space_stack_vm_start, stack_arg_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (user_space_stack_vm_start == NULL)
  {
    perror("stack segment mapping failed");
    return 1;
  };

  // 16-byte align
  user_space_stack_vm_end = (Elf64_Addr *)((unsigned long)user_space_stack_vm_start + stack_arg_size);
  char *new_args = (char *)user_space_stack_vm_end;

  size_t envc = 0;

  // copy args
  while (*t_args)
  {
    size_t len = strlen(*t_args) + 1;
    // new_args values are used to build the array of argument strings
    new_args -= len;
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
  // alloc stack
  Elf64_Addr *sp = (Elf64_Addr *)((char *)user_aux_vec - (ITEMS_SIZE((argc + envc + 2)) + AUX_VEC_SIZE));

  int user_argc = argc - 1;

  *sp++ = user_argc;

  sp = sp + argc;
  *--sp = 0UL;
  while (user_argc-- > 0)
  {
    *--sp = (Elf64_Addr)new_user_argp;
    size_t len = strlen(new_user_argp) + 1;
    new_user_argp += len;
  }

  // sp points to args
  assert(*(sp - 1) == argc - 1);
  sp = sp + argc + envc + 1;
  *--sp = 0UL;

  int user_envc = envc;
  while (user_envc-- > 0)
  {
    *--sp = (Elf64_Addr)new_user_envp;
    size_t len = strlen(new_user_envp) + 1;
    new_user_envp += len;
  }
  sp = sp - (argc + 1);

#undef PROCESS_ABI_HIGHEST_ADDR
#undef PROCESS_ABI_TEXT_SEG_ADDR
#undef RANDOM_BYTES_SIZE
#undef AUX_VEC_SIZE
#undef ITEMS_SIZE

#ifdef AUX_VECTOR_SIZE
#undef AUX_VECTOR_SIZE
#endif

// We create a fixed size auxillary vector for the elf program interpretor
#define NEW_AUX_VEC_ENT(a_type, a_val) \
  do                                   \
  {                                    \
    *--user_aux_vec = (a_type);        \
    *--user_aux_vec = (a_val);         \
  } while (0)

  NEW_AUX_VEC_ENT(AT_NULL, 0);
  NEW_AUX_VEC_ENT(AT_NOTELF, 0);
  NEW_AUX_VEC_ENT(AT_PAGESZ, page_size);
  // NEW_AUX_VEC_ENT(AT_EXECFD, open(elfpath, O_RDONLY));
  NEW_AUX_VEC_ENT(AT_PHNUM, main_Ehdr->e_phnum);
  NEW_AUX_VEC_ENT(AT_BASE, (Elf64_Addr)interp_baddr);
  NEW_AUX_VEC_ENT(AT_ENTRY, (Elf64_Addr)main_baddr + main_Ehdr->e_entry);
  NEW_AUX_VEC_ENT(AT_PHENT, main_Ehdr->e_phentsize);
  NEW_AUX_VEC_ENT(AT_FLAGS, 0);
  NEW_AUX_VEC_ENT(AT_PHDR, (Elf64_Addr)main_baddr + main_Ehdr->e_phoff);

  NEW_AUX_VEC_ENT(AT_EXECFN, *(sp - 1));

  assert((Elf64_Addr)sp % 16 == 0);
  void (*entry_point)(void) = (void (*)(void))((unsigned long)
                                                   interp_baddr +
                                               (((Elf64_Ehdr *)interp_baddr)->e_entry));

  __asm__ __volatile__("mov %0, %%rsp" : : "r"(sp));
  entry_point();
}