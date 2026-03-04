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
  int pht_i = 1;
  Elf64_Addr max_vaddr = 0;
  Elf64_Addr min_vaddr = ~0UL;
  size_t loadsegmmap_len = 0;
  Elf64_Addr pbrk = 0;
  int loagseg_i[__UINT8_MAX__] = {0};
  for (; pht_i < ehdr->e_phnum; pht_i++)
  {
    if (pht_start[pht_i].p_type == PT_INTERP && interpath)
    {
      *interpath = strdup(addr + pht_start[pht_i].p_offset);
    } // else if (pht_start[pht_i].p_type == PT_GNU_STACK){
    // check to add PROT_EXEC to stack page
    // }
    else if (pht_start[pht_i].p_type == PT_LOAD)
    {
      loagseg_i[pht_i] = pht_i;
      loadsegmmap_len += ((pht_start[pht_i].p_memsz + (page_size - 1)) & ~(page_size - 1));
      if (pht_start[pht_i].p_vaddr > max_vaddr)
      {
        max_vaddr = pht_start[pht_i].p_vaddr;
      }
      else if (pht_start[pht_i].p_vaddr <= min_vaddr)
        min_vaddr = pht_start[pht_i].p_vaddr;
    }
  }

  pht_i = 1;
  // now we reserve region
  __uint8_t *segs_addr = mmap(NULL, loadsegmmap_len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (segs_addr == MAP_FAILED)
  {
    perror("mmap failed reserving memory region");
    return NULL;
  }
  __uint8_t *baddr = segs_addr - (min_vaddr & ~(page_size - 1));
  for (; pht_i < __UINT8_MAX__; pht_i++)
  {
    if (loagseg_i[pht_i] == 0)
      continue;

    Elf64_Off relap_offset = pht_start[pht_i].p_offset & ~(page_size - 1);
    Elf64_Addr relap_vadress = pht_start[pht_i].p_vaddr & ~(page_size - 1);
    segs_addr = mmap(baddr + relap_vadress, (pht_start[pht_i].p_vaddr % page_size) + pht_start[pht_i].p_filesz, elf_pflags_to_mmap_prot(pht_start[pht_i].p_flags), MAP_PRIVATE | MAP_FIXED, fd, relap_offset);
    if (segs_addr == MAP_FAILED)
    {
      perror("mmap failed mapping individual load segments");
      return NULL;
    }
    if (pht_start[pht_i].p_memsz > pht_start[pht_i].p_filesz)
    {
      size_t bss_size = pht_start[pht_i].p_memsz - pht_start[pht_i].p_filesz;
      memset(baddr + pht_start[pht_i].p_vaddr + pht_start[pht_i].p_filesz, '\0', bss_size);
      pbrk = (Elf64_Addr)baddr + pht_start[pht_i].p_vaddr + pht_start[pht_i].p_filesz + bss_size;
    }
  }

  close(fd);
  munmap(addr, fsize);
  return baddr + min_vaddr;
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

  Usr_bckd_stck stck = {0};
  stck.sp = PROCESS_ABI_HIGHEST_ADDR;
  struct rlimit lm;
  getrlimit(RLIMIT_STACK, &lm);
  size_t stack_max_size = lm.rlim_cur;
  // start address of the vma of the stack segment
  __uint8_t *stck_vma_start = (__uint8_t *)((Elf64_Addr)PROCESS_ABI_HIGHEST_ADDR - stack_max_size);

  stck.argc = argc - 1;

  int cpy_i;

  // we skip the name of the main executable file
  char **t_args = args + 1;
  char **t_envp = envp;

  size_t t_args_size = 0;
  while (*t_args)
  {
    t_args_size += (strlen(*t_args) + 1);
    t_args++;
  }

  size_t t_env_size = 0;
  while (*t_envp)
  {
    t_env_size += (strlen(*t_envp) + 1);
    stck.envc++;
    t_envp++;
  }
  // we temporarily setup the stack in the heap
  size_t len = sizeof(Usr_bckd_stck) + t_args_size + t_env_size + RANDOM_BYTES_SIZE + AUX_VEC_SIZE + ITEMS_SIZE(stck.envc + 1) + ITEMS_SIZE(stck.argc + 1) + ITEMS_SIZE(1) + (RANDOM_BYTES_SIZE - 1);

  __uint8_t *temp = (__uint8_t *)malloc(len);
  if (temp == NULL)
  {
    perror("Temporal memory allocation to hold userspace,args and envp failed");
    return 1;
  };

  t_args = args + 1;
  t_envp = envp;

  Elf64_Addr des = (Elf64_Addr)temp + sizeof(Usr_bckd_stck);
  // copy args
  while (*t_args)
  {
    size_t len = strlen(*t_args) + 1;
    memcpy((void *)des, *t_args, len);
    des += len;
    t_args++;
  }
  des = (Elf64_Addr)temp + sizeof(Usr_bckd_stck) + t_args_size;
  // copy env
  while (*t_envp)
  {
    size_t len = strlen(*t_envp) + 1;
    memcpy((void *)des, *t_envp, len);
    des += len;
    t_envp++;
  }

  Usr_bckd_stck *stckptr = (Usr_bckd_stck *)temp;
  stckptr->sp = stck.sp;
  stckptr->argc = stck.argc;
  stckptr->envc = stck.envc;
  stckptr->argp = (char *)((unsigned long)stckptr + sizeof(Usr_bckd_stck));
  stckptr->envp = (unsigned char *)(stckptr->argp + t_args_size);

  Elf64_Addr *h_sp = (Elf64_Addr *)((unsigned long)(temp + len) & ~15);

  *h_sp-- = stck.argc;

  // store the distance between the positions as we will copy into a new region
  while (stck.argc-- > 0)
  {
    *h_sp-- = (Elf64_Addr)h_sp - (Elf64_Addr)stckptr->argp;
    size_t len = strlen(stckptr->argp) + 1;
    stckptr->argp += len;
  }
  *h_sp-- = 0UL;
  while (stck.envc-- > 0)
  {
    *h_sp-- = (Elf64_Addr)h_sp - (Elf64_Addr)stckptr->envp;
    size_t len = strlen(stckptr->envp) + 1;
    stckptr->envp += len;
  }
  *h_sp-- = 0UL;

  // restore argc,envc values
  stck.argc = stckptr->argc;
  stck.envc = stckptr->envc;

#undef PROCESS_ABI_HIGHEST_ADDR
#undef PROCESS_ABI_TEXT_SEG_ADDR
#undef RANDOM_BYTES_SIZE
#undef AUX_VEC_SIZE
#undef ITEMS_SIZE

#ifdef AUX_VECTOR_SIZE
#undef AUX_VECTOR_SIZE
#endif

// We create a fixed size auxillary vector for the elf program interpretor
#define NEW_AUX_VEV_ET(a_type, a_un) ({*h_sp--=a_un;*h_sp--=a_type; })
  NEW_AUX_VEV_ET(AT_NOTELF, 0);
  NEW_AUX_VEV_ET(AT_PAGESZ, page_size);
  // NEW_AUX_VEV_ET(AT_EXECFD, open(elfpath, O_RDONLY));
  NEW_AUX_VEV_ET(AT_PHNUM, main_Ehdr->e_phnum);
  NEW_AUX_VEV_ET(AT_BASE, (Elf64_Addr)interp_baddr);
  NEW_AUX_VEV_ET(AT_ENTRY, (Elf64_Addr)main_baddr + main_Ehdr->e_entry);
  NEW_AUX_VEV_ET(AT_PHENT, main_Ehdr->e_phentsize);
  NEW_AUX_VEV_ET(AT_FLAGS, 0);
  NEW_AUX_VEV_ET(AT_PHDR, (Elf64_Addr)main_baddr + main_Ehdr->e_phoff);

  // create stack segment
  stck_vma_start = mmap(stck_vma_start, stack_max_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stck_vma_start == NULL)
  {
    perror("stack segment mapping failed");
    return 1;
  };

  // stack top
  Elf64_Addr *stck_vma_end = (Elf64_Addr *)((unsigned long)stck_vma_start + stack_max_size);

  // command-line arguments, environmental variables
  stckptr->argp = (char *)((unsigned long)stck_vma_end + sizeof(Usr_bckd_stck));
  stckptr->envp = stckptr->argp + t_args_size;
  // add file name entry
  NEW_AUX_VEV_ET(AT_EXECFN, (Elf64_Addr)stckptr->argp);
  NEW_AUX_VEV_ET(AT_NULL, 0);

  // stck_vma_end sizeof(Usr_bckd_stck) + t_args_size
  // fix should rather be the top of the stack
  stck_vma_end = (Elf64_Addr *)((unsigned long)stck_vma_end - len);

  memcpy(stck_vma_end, temp, len);

  free(temp);

  stckptr->sp = (Elf64_Addr *)((unsigned long)(stck_vma_end) & ~15UL);

  stck_vma_end = (Elf64_Addr *)((unsigned long)(stck_vma_end) & ~15UL);
  assert(*stck_vma_end-- == stck.argc);

  while (stck.argc-- > 0)
    *stck_vma_end-- = (unsigned long)(*stck_vma_end) + (unsigned long)stck_vma_end;

  stck_vma_end--;
  while (stck.envc-- > 0)
    *stck_vma_end-- = (unsigned long)(*stck_vma_end) + (unsigned long)stck_vma_end;

  stck_vma_end--;

  void (*entry_point)(void) = (void (*)(void))((unsigned long)
                                                   interp_baddr +
                                               ((Elf64_Ehdr *)interp_baddr)->e_entry);

  __asm__ __volatile__("mov %0, %%rsp" : : "r"(stckptr->sp));
  entry_point();
}