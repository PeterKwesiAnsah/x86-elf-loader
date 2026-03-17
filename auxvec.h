#ifndef _UAPI_LINUX_AUXVEC_H
#define _UAPI_LINUX_AUXVEC_H

/* Symbolic values for the entries in the auxiliary table,not indexes into a table
   put on the initial stack */
#define AT_NULL 0   /* end of vector */
#define AT_IGNORE 1 /* entry should be ignored */
#define AT_EXECFD 2 /* file descriptor of program */
#define AT_PHDR 3   /* program headers for program */
#define AT_PHENT 4  /* size of program header entry */
#define AT_PHNUM 5  /* number of program headers */
#define AT_PAGESZ 6 /* system page size */
#define AT_BASE 7   /* base address of interpreter */
#define AT_FLAGS 8  /* flags */
#define AT_ENTRY 9  /* entry point of program */
#define AT_RANDOM 25
#define AT_SYSINFO_EHDR 33
#define AT_EXECFN 31 /* filename of program */

#define AUX_VECTOR_SIZE 12

typedef struct
{
   int a_type;
   union
   {
      long a_val;
      void *a_ptr;
      void (*a_fnc)();
   } a_un;
} auxv_t;

#endif /* _UAPI_LINUX_AUXVEC_H */