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
        max_vaddr = ((pht_start[pht_i].p_vaddr + pht_start[pht_i].p_memsz) + page_size - 1) & ~(page_size - 1);
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
  loadsegmmap_len = max_vaddr - (min_vaddr & ~(page_size - 1));
  assert(loadsegmmap_len % page_size == 0);

  // now we reserve region
  __uint8_t *segs_addr = mmap(s_addr, loadsegmmap_len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (segs_addr == MAP_FAILED)
  {
    perror("mmap failed reserving memory region");
    return NULL;
  }

  assert(min_vaddr == 0UL);

  __uint8_t *baddr = segs_addr - (min_vaddr & ~(page_size - 1));

  for (int pht_i = 0; pht_i < ehdr->e_phnum; pht_i++)
  {
    if (pht_start[pht_i].p_type == PT_LOAD)
    {
      Elf64_Off relap_offset = pht_start[pht_i].p_offset & ~(page_size - 1);
      Elf64_Addr relap_vadress = pht_start[pht_i].p_vaddr & ~(page_size - 1);

      size_t map_size = (pht_start[pht_i].p_vaddr % page_size) + pht_start[pht_i].p_memsz;
      map_size = (map_size + page_size - 1) & ~(page_size - 1);

      segs_addr = mmap(baddr + relap_vadress, map_size, elf_pflags_to_mmap_prot(pht_start[pht_i].p_flags), MAP_PRIVATE | MAP_FIXED, fd, relap_offset);
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
  void *main_baddr = LoadET((void *)PROCESS_ABI_TEXT_SEG_ADDR, open(elfpath, O_RDONLY), page_size, &interpath);
  if (main_baddr == NULL)
    return 1;
  Elf64_Ehdr *main_Ehdr = (Elf64_Ehdr *)main_baddr;

  // We assume the executable object file is associated with dynamic linking
  void *interp_baddr = LoadET(NULL, open(interpath, O_RDONLY), page_size, NULL);
  if (interp_baddr == NULL)
    return 1;

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

  user_aux_vec = sp + argc + envc + 2;
// We create a fixed size auxillary vector for the elf program interpretor
#define NEW_AUX_VEC_ENT(a_type, a_val) \
  do                                   \
  {                                    \
    *user_aux_vec++ = (a_val);         \
    *user_aux_vec++ = (a_type);        \
  } while (0)

  NEW_AUX_VEC_ENT(AT_EXECFN, *(sp + 1));
  NEW_AUX_VEC_ENT(AT_PAGESZ, page_size);
  NEW_AUX_VEC_ENT(AT_EXECFD, open(elfpath, O_RDONLY));
  NEW_AUX_VEC_ENT(AT_PHNUM, main_Ehdr->e_phnum);
  NEW_AUX_VEC_ENT(AT_BASE, (Elf64_Addr)interp_baddr);
  NEW_AUX_VEC_ENT(AT_ENTRY, (Elf64_Addr)main_baddr + main_Ehdr->e_entry);
  NEW_AUX_VEC_ENT(AT_PHENT, main_Ehdr->e_phentsize);
  NEW_AUX_VEC_ENT(AT_FLAGS, 0);
  NEW_AUX_VEC_ENT(AT_PHDR, (Elf64_Addr)main_baddr + main_Ehdr->e_phoff);

  unsigned char random_bytes[16];
  int urandom = open("/dev/urandom", O_RDONLY);
  read(urandom, random_bytes, 16);
  close(urandom);
  // random bytes points to the old stack of the loader process
  // since we are not trying to replace that stack it should be valid memory address
  // TODO: set it up in the new stack
  NEW_AUX_VEC_ENT(AT_RANDOM, (Elf64_Addr)random_bytes);
  NEW_AUX_VEC_ENT(AT_NULL, 0);

  assert((Elf64_Addr)sp % 16 == 0);
  assert(*sp == argc - 1);
  void (*entry_point)(void) = (void (*)(void))((unsigned long)
                                                   interp_baddr +
                                               (((Elf64_Ehdr *)interp_baddr)->e_entry));

  assert(entry_point != (void *)0);
  assert(interp_baddr != (void *)0);

  __asm__ __volatile__(
      "mov %0, %%rsp\n"
      "xor %%rbp, %%rbp\n"
      "jmp *%1"
      :
      : "r"(sp), "r"(entry_point));
}