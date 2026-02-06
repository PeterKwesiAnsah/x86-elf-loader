// Header file to parse and interpret ELF (Executable and Linkable Format) files
#ifndef ELF_H
#define ELF_H
/* e_ident size */
#define EI_NIDENT 16


// ELF e_ident[] index values
enum ElfEI {
    EI_MAG0        = 0,  // File identification
    EI_MAG1        = 1,  // File identification
    EI_MAG2        = 2,  // File identification
    EI_MAG3        = 3,  // File identification
    EI_CLASS       = 4,  // File class
    EI_DATA        = 5,  // Data encoding
    EI_VERSION     = 6,  // File version
    EI_OSABI       = 7,  // Operating system/ABI identification
    EI_ABIVERSION  = 8,  // ABI version
    EI_PAD         = 9   // Start of padding bytes
    // (There’s also EI_NIDENT = 16, but that’s not an index for a specific field)
};


/* Basic ELF types */
typedef unsigned char   Elf64_Byte;
typedef unsigned short  Elf64_Half;
typedef unsigned int    Elf64_Word;
typedef signed int      Elf64_Sword;
typedef unsigned long   Elf64_Xword;
typedef signed long     Elf64_Sxword;
typedef unsigned long   Elf64_Addr;
typedef unsigned long   Elf64_Off;



/* ELF64 file header */
typedef struct {
    unsigned char e_ident[EI_NIDENT]; /* ELF identification */
    Elf64_Half    e_type;              /* Object file type */
    Elf64_Half    e_machine;           /* Architecture */
    Elf64_Word    e_version;           /* Object file version */
    Elf64_Addr    e_entry;             /* Entry point address */
    Elf64_Off     e_phoff;             /* Program header table offset */
    Elf64_Off     e_shoff;             /* Section header table offset */
    Elf64_Word    e_flags;             /* Processor-specific flags */
    Elf64_Half    e_ehsize;             /* ELF header size */
    Elf64_Half    e_phentsize;          /* Program header entry size */
    Elf64_Half    e_phnum;              /* Program header entry count */
    Elf64_Half    e_shentsize;          /* Section header entry size */
    Elf64_Half    e_shnum;              /* Section header entry count */
    Elf64_Half    e_shstrndx;            /* Section header string table index */
} Elf64_Ehdr;

typedef struct {
    Elf64_Word  sh_name;       /* Section name (index into section header string table) */
    Elf64_Word  sh_type;       /* Section type (e.g., SHT_PROGBITS, SHT_NOBITS, SHT_SYMTAB) */
    Elf64_Xword sh_flags;      /* Section flags (e.g., writable, allocatable, executable) */
    Elf64_Addr  sh_addr;       /* Virtual address of section in memory (0 for non-allocated sections) */
    Elf64_Off   sh_offset;     /* Offset of section in file image */
    Elf64_Xword sh_size;       /* Size of section in bytes */
    Elf64_Word  sh_link;       /* Section-specific link info (depends on section type) */
    Elf64_Word  sh_info;       /* Extra info (depends on section type, e.g., symbol table) */
    Elf64_Xword sh_addralign;  /* Alignment constraint (must be power of two, 0 or 1 = no alignment) */
    Elf64_Xword sh_entsize;    /* Size of each entry if section holds fixed-size entries (0 otherwise) */
} Elf64_Shdr;

typedef struct {
    Elf64_Word  p_type;
    Elf64_Word  p_flags;
    Elf64_Off   p_offset;
    Elf64_Addr  p_vaddr;
    Elf64_Addr  p_paddr;
    Elf64_Xword p_filesz;
    Elf64_Xword p_memsz;
    Elf64_Xword p_align;
} Elf64_Phdr;

typedef enum {
    PT_NULL    = 0,
    PT_LOAD    = 1,
    PT_DYNAMIC = 2,
    PT_INTERP  = 3,
    PT_NOTE    = 4,
    PT_SHLIB   = 5,
    PT_PHDR    = 6,
    PT_TLS     = 7,

    PT_LOOS    = 0x60000000,
    PT_HIOS    = 0x6fffffff,

    PT_LOPROC  = 0x70000000,
    PT_HIPROC  = 0x7fffffff
} Elf_Phdr_Type;


typedef enum {
    SHT_NULL           = 0,
    SHT_PROGBITS       = 1,
    SHT_SYMTAB         = 2,
    SHT_STRTAB         = 3,
    SHT_RELA           = 4,
    SHT_HASH           = 5,
    SHT_DYNAMIC        = 6,
    SHT_NOTE           = 7,
    SHT_NOBITS         = 8,
    SHT_REL            = 9,
    SHT_SHLIB          = 10,
    SHT_DYNSYM         = 11,

    SHT_INIT_ARRAY     = 14,
    SHT_FINI_ARRAY     = 15,
    SHT_PREINIT_ARRAY  = 16,
    SHT_GROUP          = 17,
    SHT_SYMTAB_SHNDX   = 18,
    SHT_RELR           = 19,

    /* OS-specific */
    SHT_LOOS           = 0x60000000,
    SHT_HIOS           = 0x6fffffff,

    /* Processor-specific */
    SHT_LOPROC         = 0x70000000,
    SHT_HIPROC         = 0x7fffffff,

    /* Application-specific */
    SHT_LOUSER         = 0x80000000,
    SHT_HIUSER         = 0xffffffff
} Elf_SectionType;


typedef enum {
    PF_NONE = 0,        // no permissions

    PF_X = 1 << 0,      // Execute
    PF_W = 1 << 1,      // Write
    PF_R = 1 << 2       // Read
} Elf_PFlags;


#endif
