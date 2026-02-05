#include "elf.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MIN_ARG_COUNT 2

// Usage ./loader <path-to-elf-file> [CLI args to be passed to during process
// execution of the program]
int main(int argc, char **args)
{
  pid_t childpid;
  
  if (argc < MIN_ARG_COUNT)
    return 1;

  const char *elfpath = args[1];
  int fd = open(elfpath, O_RDONLY);

  // Source - https://stackoverflow.com/a/6537560
  // Posted by Hasturkun
  // Retrieved 2026-01-30, License - CC BY-SA 3.0
  off_t fsize;

  fsize = lseek(fd, 0, SEEK_END);
  void *addr = mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  close(fd);
  if (addr == MAP_FAILED)
  {
    perror("mmap failed");
    return 1;
  }
  Elf64_Ehdr ehdr;
  memcpy(&ehdr, addr, sizeof(ehdr));

  if ((childpid = fork()) == 0)
  {
    __uint8_t *baddr = NULL;
    Elf64_Phdr *pht_start = (__uint8_t *)addr + ehdr.e_phoff;

    int pht_i = 1;
    for (; pht_i < ehdr.e_phnum; pht_i++)
    {
      if (pht_start[pht_i].p_type == PT_LOAD)
        break;
    }
    // Note: This codes for PIE (ELF-DYN)
    Elf64_Phdr lowloadseg = pht_start[pht_i];
    void *map_addr = mmap(NULL, lowloadseg.p_memsz, lowloadseg.p_flags, MAP_PRIVATE, fd, lowloadseg.p_offset);
    baddr = map_addr - lowloadseg.p_vaddr;
    void *p_entry = baddr + ehdr.e_entry;
    pht_i++;
    for (; pht_i < ehdr.e_phnum; pht_i++)
    {
      lowloadseg = pht_start[pht_i];
      if (pht_start[pht_i].p_type != PT_LOAD)
        continue;
      void *map_addr = mmap(baddr + lowloadseg.p_vaddr, lowloadseg.p_memsz, lowloadseg.p_flags, MAP_PRIVATE, fd, lowloadseg.p_offset);
    }
    // TODO: Compare the relative distances between file pages and memory mapped pages
  }
  // TODO: suspend parent process till child process finishes

  return 0;
}
