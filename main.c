#include "elf.h"
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

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
  __uint8_t *addr = mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (addr == MAP_FAILED)
  {
    perror("mmap failed");
    return 1;
  }
  Elf64_Ehdr ehdr;
  memcpy(&ehdr, addr, sizeof(ehdr));
  size_t page_size = sysconf(_SC_PAGE_SIZE);
  int sht_i = 1;
  Elf64_Xword bss_size;
  Elf64_Shdr *sht_start = (Elf64_Shdr *)(addr + ehdr.e_shoff);

  while (sht_start[sht_i].sh_type != SHT_NOBITS)
  {
    sht_i++;
  }
  bss_size = sht_start[sht_i].sh_size;

  __uint8_t *baddr = (__uint8_t *)0;
  Elf64_Phdr *pht_start = (Elf64_Phdr *)(addr + ehdr.e_phoff);
  __uint8_t pt_load_cnts = 1;
  int pht_i = 1;
  while (pht_start[pht_i].p_type != PT_LOAD)
  {
    pht_i++;
  };
  Elf64_Addr vmaddr[__UINT8_MAX__];
  Elf64_Addr fpaddr[__UINT8_MAX__];
  Elf64_Addr *vmaddr_ptr = vmaddr;
  Elf64_Addr *fpaddr_ptr = fpaddr;

  __uint8_t *map_addr;
  // Note: This codes for PIE (ELF-DYN)
  Elf64_Phdr loadseg = pht_start[pht_i];
  // NB:loadseg.p_filesz must be a multiple of sysconf(SC_PAGE_SIZE)
  size_t mmap_length = loadseg.p_filesz;
  // file mapping is not enough, .bss tailed loadsegment
  if (loadseg.p_memsz > loadseg.p_filesz)
  {
    // mmap_length = ((mmap_length + bss_size) + page_size - 1) & ~(page_size - 1);
    // map_addr = mmap(NULL, mmap_length, elf_pflags_to_mmap_prot((int)loadseg.p_flags), MAP_PRIVATE, fd, loadseg.p_offset);

    // if (map_addr == MAP_FAILED)
    // {
    //   perror("mmap failed:mapping the lowest file page");
    //   return 1;
    // }
    // memset(map_addr + loadseg.p_filesz, '\0', bss_size);
  }
  else
  {
    mmap_length = ((mmap_length + 0) + page_size - 1) & ~(page_size - 1);
    map_addr = mmap(NULL, loadseg.p_filesz, elf_pflags_to_mmap_prot((int)loadseg.p_flags), MAP_PRIVATE, fd, loadseg.p_offset);
    if (map_addr == MAP_FAILED)
    {
      perror("mmap failed:mapping the lowest file page");
      return 1;
    }
  }

  *vmaddr_ptr++ = (Elf64_Addr)map_addr;
  *fpaddr_ptr++ = (Elf64_Addr)loadseg.p_offset;

  baddr = map_addr - (((loadseg.p_vaddr + page_size) - 1) & ~(page_size - 1));
  __uint8_t *p_entry = baddr + ehdr.e_entry;

  pht_i++;
  for (; pht_i < ehdr.e_phnum; pht_i++)
  {
    loadseg = pht_start[pht_i];
    if (pht_start[pht_i].p_type != PT_LOAD)
      continue;

    size_t mmap_length = loadseg.p_filesz;
    size_t mmap_offset = loadseg.p_offset;
    map_addr = baddr + (((loadseg.p_vaddr + page_size) - 1) & ~(page_size - 1));
    //file mapping is not enough, .bss tailed loadsegment
    if (loadseg.p_memsz > loadseg.p_filesz)
    {
      // mmap_length = ((mmap_length + bss_size) + page_size - 1) & ~(page_size - 1);
      // mmap_offset = (mmap_offset + page_size - 1) & ~(page_size - 1);
      // assert((((size_t)map_addr % page_size) == 0));
      // map_addr = mmap(map_addr, mmap_length, elf_pflags_to_mmap_prot((int)loadseg.p_flags), MAP_PRIVATE, fd, mmap_offset);

      // if (map_addr == MAP_FAILED)
      // {
      //   perror("mmap failed:mapping a file page");
      //   return 1;
      // }
      // memset(map_addr + loadseg.p_filesz, '\0', bss_size);
    }
    else
    {
      mmap_length = ((mmap_length + page_size) - 1) & ~(page_size - 1);
      mmap_offset = (mmap_offset + page_size - 1) & ~(page_size - 1);
      assert(((size_t)map_addr % page_size) == 0);
      map_addr = mmap(map_addr, mmap_length, elf_pflags_to_mmap_prot((int)loadseg.p_flags), MAP_PRIVATE, fd, mmap_offset);
      if (map_addr == MAP_FAILED)
      {
        perror("mmap failed: mapping the a file page");
        return 1;
      }
    }

    pt_load_cnts++;
    *vmaddr_ptr++ = (Elf64_Addr)map_addr;
    *fpaddr_ptr++ = (Elf64_Addr)loadseg.p_offset;
  }

  // TODO: Compare the relative distances between file pages and memory mapped pages
  for (pht_i = 0; pht_i + 1 < pt_load_cnts; pht_i++)
  {
    assert((vmaddr[pht_i + 1] - vmaddr[pht_i]) == (fpaddr[pht_i + 1] - fpaddr[pht_i]));
  }
  // TODO: suspend parent process till child process finishes
  return 0;
}