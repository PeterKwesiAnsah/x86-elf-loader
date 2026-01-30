#include "elf.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>


#define MIN_ARG_COUNT 2

// Usage ./loader <path-to-elf-file> [CLI args to be passed to during process
// execution of the program]
int main(int argc, char **args) {
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
  if(addr==MAP_FAILED){
      perror("mmap failed");
      return 1;
  }
  Elf64_Ehdr ehdr;
  memcpy(&ehdr,addr, sizeof(ehdr));
  return 0;
}
