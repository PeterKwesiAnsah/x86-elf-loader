#include "elf.h"
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

#define MIN_ARG_COUNT 2

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
int LoadET(int fd, size_t page_size, char **interpath)
{

  off_t fsize = lseek(fd, 0, SEEK_END);
  __uint8_t *addr = mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (addr == MAP_FAILED)
  {
    perror("mmap failed");
    return 1;
  }

  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)addr;
  __uint8_t *baddr = (__uint8_t *)0;
  Elf64_Phdr *pht_start = (Elf64_Phdr *)(addr + ehdr->e_phoff);

  int pht_i = 1;
  // TODO: change the access protections
  for (; pht_i < ehdr->e_phnum; pht_i++)
  {
    if (pht_start[pht_i].p_type == PT_INTERP)
    {
      *interpath = (char *)addr + pht_start[pht_i].p_offset;
    }
    else if (pht_start[pht_i].p_type == PT_LOAD)
    {
      //These file page segments automatically have corresponding memory page-bounded segments
      if (addr + pht_start[pht_i].p_offset % page_size==0)
      {
        int status = mprotect(addr + pht_start[pht_i].p_offset, pht_start[pht_i].p_filesz, elf_pflags_to_mmap_prot((int)pht_start[pht_i].p_flags));
        if (status < 0)
        {
          perror("mprotect failed");
          return 1;
        }     
      }
      //While these file page segments are relative to page-aligned file segments as thier memory counter parts too
      else
      {
        Elf64_Off relap_offset= pht_start[pht_i].p_offset & ~(page_size - 1);
        Elf64_Addr relap_vadress=pht_start[pht_i].p_vaddr & ~(page_size - 1);
      }
    }

    pht_i++;
  };
  // close(fd);
  // setup stack
  // setup a memory image for program interpretor
  //  jump to _start
  return 0;
}

// Usage ./loader <path-to-elf-file> [CLI args to be passed to during process
// execution of the program]
int main(int argc, char **args)
{
  pid_t childpid = 0;

  if (argc < MIN_ARG_COUNT)
    return 1;

  const char *elfpath = args[1];
  int fd = open(elfpath, O_RDONLY);

  size_t page_size = sysconf(_SC_PAGE_SIZE);

  if ((childpid = fork()) == 0)
  {
    char *interpath = NULL;
    int status = LoadET(fd, page_size, &interpath);
    printf("%s\n", interpath);
    return status;
  }

  /* If we forked above, wait for the child so the parent suspends until child exits. */
  if (childpid > 0)
  {
    int status = 0;
    if (waitpid(childpid, &status, 0) == -1)
    {
      perror("waitpid failed");
      return 1;
    }
    if (WIFEXITED(status))
      return WEXITSTATUS(status);
    return 0;
  }

  return 0;
}